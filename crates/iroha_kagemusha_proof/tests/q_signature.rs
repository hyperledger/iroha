//! Public signature binding, total failure paths and actual native Q proofs.

mod common;
use ff::Field;
use iroha_kagemusha_proof::q_signature::{
    QSignatureCircuit, QSignaturePlan, SignatureKey, SignatureSlot, SignatureWitness,
    native::{QSignatureError, QSignatureProver},
};
use iroha_pasta::{Fq, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig,
    check::{CheckMode, check_circuit},
    frontend::{Circuit, configure, synthesize},
    keys::{CosetCachePolicy, KeygenConfigV2, keygen_pk_v2, pk::artifact::ReadConfig},
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    ff::Nat,
    p256::{
        VerifyMode,
        native::{self, Affine, HALF_N, N, ORDER, P},
    },
    sha256::native::sha256_of_digest,
};

fn words(bytes: [u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| {
        u64::from_be_bytes(bytes[(3 - i) * 8..(4 - i) * 8].try_into().unwrap())
    })
}
fn witness() -> SignatureWitness {
    let digest = iroha_pasta::Fp::from(123);
    let message = words(sha256_of_digest(&digest));
    let secret = [17, 0, 0, 0];
    let nonce = [19, 0, 0, 0];
    let key = native::mul(&Affine::GENERATOR, &secret).unwrap();
    let r = ORDER.reduce_once(&native::mul(&Affine::GENERATOR, &nonce).unwrap().x);
    let mut s = ORDER.mul(
        &ORDER.inverse(&nonce),
        &ORDER.add(&ORDER.reduce_once(&message), &ORDER.mul(&r, &secret)),
    );
    if native::words_cmp(&s, &HALF_N).is_gt() {
        s = ORDER.neg(&s);
    }
    assert!(native::verify_prehashed(&message, &r, &s, &key));
    SignatureWitness {
        digest,
        key: [key.x, key.y],
        signature: [r, s],
    }
}
fn oracle(w: &SignatureWitness) -> bool {
    native::verify_prehashed(
        &words(sha256_of_digest(&w.digest)),
        &w.signature[0],
        &w.signature[1],
        &Affine {
            x: w.key[0],
            y: w.key[1],
        },
    )
}
fn circuit(w: SignatureWitness, mode: VerifyMode, fixed: bool) -> QSignatureCircuit {
    let key = if fixed {
        SignatureKey::Fixed(Affine {
            x: w.key[0],
            y: w.key[1],
        })
    } else {
        SignatureKey::Variable
    };
    QSignatureCircuit::new(
        QSignaturePlan::new(vec![SignatureSlot { mode, key }]).unwrap(),
        vec![w],
    )
    .unwrap()
}
fn satisfied(c: &QSignatureCircuit, public: &[Vec<Fq>]) -> bool {
    check_circuit(c, 16, public, CheckMode::Strict)
        .unwrap()
        .is_satisfied()
}
#[test]
fn signature_plan_rejects_invalid_shapes_and_fixed_keys() {
    assert!(QSignaturePlan::new(vec![]).is_err());
    let slot = SignatureSlot {
        mode: VerifyMode::Soft,
        key: SignatureKey::Variable,
    };
    assert!(QSignaturePlan::new(vec![slot; 6]).is_err());
    assert!(QSignaturePlan::new(vec![slot; 7]).is_err());
    assert!(
        QSignaturePlan::new(vec![SignatureSlot {
            key: SignatureKey::Fixed(Affine { x: P, y: [0; 4] }),
            ..slot
        }])
        .is_err()
    );
    let keys = (1..=3)
        .map(|d| SignatureSlot {
            key: SignatureKey::Fixed(native::mul(&Affine::GENERATOR, &[d, 0, 0, 0]).unwrap()),
            ..slot
        })
        .collect();
    assert!(QSignaturePlan::new(keys).is_err());
    let plan = QSignaturePlan::new(vec![slot]).unwrap();
    assert!(QSignatureCircuit::new(plan, vec![]).is_err());
    assert!(
        circuit(witness(), VerifyMode::Hard, false)
            .instances(&[])
            .is_err()
    );
}
#[test]
fn signature_honest_layout_and_all_public_inputs_bound() {
    let w = witness();
    for fixed in [false, true] {
        let c = circuit(w, VerifyMode::Hard, fixed);
        let public = c.instances(&[true]).unwrap();
        assert!(satisfied(&c, &public));
        let (cs, _) = configure(&c).unwrap();
        assert_eq!(cs.num_advice_columns(), 17);
        assert_eq!(cs.lookups().len(), 10);
        assert_eq!(cs.permutation().columns().len(), 12);
        let known = synthesize(&c, 16, Some(&public)).unwrap();
        let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        for i in 0..10 {
            let mut wrong = public.clone();
            wrong[0][i] += Fq::ONE;
            assert!(!satisfied(&c, &wrong), "public slot{i} fixed{fixed}");
        }
        if fixed {
            let mut other = w;
            other.key[0][0] ^= 1;
            let forged = QSignatureCircuit::new(c.plan().clone(), vec![other]).unwrap();
            assert!(!satisfied(&forged, &forged.instances(&[true]).unwrap()));
        }
        let flags = known.tables.advice_assigned();
        let rows = flags
            .iter()
            .filter_map(|col| col.iter().rposition(|v| *v))
            .max()
            .unwrap()
            + 1;
        let cells = flags.iter().flatten().filter(|v| **v).count();
        eprintln!("signature fixed{fixed}: rows{rows} cells{cells}");
    }
}
#[test]
fn signature_soft_raw_256_bit_boundaries_and_consistent_aliases() {
    let original = witness();
    let mut cases = vec![original];
    for component in 0..4 {
        for boundary in [
            [0; 4],
            [u64::MAX; 4],
            if component < 2 { P } else { N },
            [0, 0, 0, 1 << 63],
        ] {
            let mut altered = original;
            if component < 2 {
                altered.key[component] = boundary;
            } else {
                altered.signature[component - 2] = boundary;
            }
            cases.push(altered);
        }
    }
    let mut high_s = original;
    high_s.signature[1] = ORDER.neg(&high_s.signature[1]);
    cases.push(high_s);
    let mut off_curve = original;
    off_curve.key[1][0] ^= 1;
    cases.push(off_curve);
    let mut wrong_digest = original;
    wrong_digest.digest += iroha_pasta::Fp::ONE;
    cases.push(wrong_digest);
    for (i, w) in cases.into_iter().enumerate() {
        let verdict = oracle(&w);
        let c = circuit(w, VerifyMode::Soft, false);
        assert!(satisfied(&c, &c.instances(&[verdict]).unwrap()), "case{i}");
        assert!(
            !satisfied(&c, &c.instances(&[!verdict]).unwrap()),
            "forged verdict{i}"
        );
    }
    // A raw integer changed by the native Fq modulus has the same field
    // residue, but distinct exported 128-bit halves and must not alias.
    let modulus = Nat::from_words(iroha_plonk_gadgets::ff::ForeignModulus::PASTA_FQ.words());
    let mut a = original;
    a.signature[0] = [7, 0, 0, 0];
    let mut b = a;
    b.signature[0] = modulus.wrapping_add(&Nat::from_u64(7)).low_words();
    let a = circuit(a, VerifyMode::Soft, false);
    let b = circuit(b, VerifyMode::Soft, false);
    assert!(!satisfied(&b, &a.instances(&[false]).unwrap()));
    let mut bad = original;
    bad.signature[1] = [0; 4];
    let hard = circuit(bad, VerifyMode::Hard, false);
    assert!(!satisfied(&hard, &hard.instances(&[false]).unwrap()));
}
#[test]
fn signature_five_variable_one_fixed_fits_shared_k16() {
    let w = witness();
    let mut slots = vec![
        SignatureSlot {
            mode: VerifyMode::Soft,
            key: SignatureKey::Variable
        };
        5
    ];
    slots.push(SignatureSlot {
        mode: VerifyMode::Hard,
        key: SignatureKey::Fixed(Affine {
            x: w.key[0],
            y: w.key[1],
        }),
    });
    let c = QSignatureCircuit::new(QSignaturePlan::new(slots).unwrap(), vec![w; 6]).unwrap();
    let instances = c.instances(&[true; 6]).unwrap();
    assert!(satisfied(&c, &instances));
    let s = synthesize(&c, 16, Some(&instances)).unwrap();
    let flags = s.tables.advice_assigned();
    let rows = flags
        .iter()
        .filter_map(|col| col.iter().rposition(|v| *v))
        .max()
        .unwrap()
        + 1;
    let cells = flags.iter().flatten().filter(|v| **v).count();
    eprintln!("signature5V1F: rows{rows} cells{cells}");
    assert!(rows <= 65_530);
}
#[test]
#[ignore = "optimized actual native keygen/proof qualification component"]
fn signature_actual_native_proof_binds_inputs_and_retains_opening() {
    let c = circuit(witness(), VerifyMode::Hard, false);
    let public = c.instances(&[true]).unwrap();
    let params = iroha_plonk::pcs::ipa::PinnedParams::<iroha_pasta::Ep>::derive(16).unwrap();
    let mut config = KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec());
    config.compress_selectors = false;
    let key = keygen_pk_v2(&params, &c, &config).unwrap();
    let original = key.artifact_bytes_v2().unwrap();
    let installed = QSignatureProver::from_original_artifact(
        c.plan().clone(),
        params.clone(),
        key.binding().encoded(),
        key.vk().to_bytes(),
        &original,
        signature_read_config(&original),
    )
    .unwrap();
    assert_eq!(installed.binding(), key.binding());
    assert_eq!(installed.verifying_key().to_bytes(), key.vk().to_bytes());
    let (bound_d, bound_v, seal) = installed.into_metadata().into_parts();
    let view = seal.bind(&bound_d, &bound_v, None).unwrap();
    assert!(core::ptr::eq(view.binding(), &bound_d));
    assert!(core::ptr::eq(view.verifying_key(), &bound_v));
    let installed =
        iroha_kagemusha_proof::q_signature::native::QSignatureProverView::from_source_bound(
            c.plan(),
            &params,
            view,
        )
        .unwrap();
    // Compare the actual rebuilt proof with this fresh key, using the same public
    // test-only recovery stream. No PK accessor or cached proving material remains.
    let direct_witness = iroha_plonk::Witness::from_circuit(&key, &c, &public).unwrap();
    let direct = iroha_plonk::create_proof_owned(
        &params,
        &key,
        direct_witness,
        common::recovery(119),
        ProverConfig::default(),
    )
    .unwrap();
    iroha_plonk::verifier::verify_full(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &direct,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    let cancelled = iroha_pasta::CancellationToken::new();
    cancelled.cancel();
    let never_draw = || {
        iroha_plonk::ProverRandomness::recovery(
            |_: &[u8; 32]| -> Result<rand_chacha::ChaCha20Rng, ()> {
                panic!("cancelled signature proof consumed recovery entropy")
            },
        )
    };
    let cancellation_config = ProverConfig {
        cancellation: Some(&cancelled),
        ..ProverConfig::default()
    };
    let error = installed
        .prove(&[witness()], never_draw(), cancellation_config)
        .unwrap_err();
    assert!(error.is_cancelled());
    let error = QSignatureProver::from_original_artifact_cancellable(
        c.plan().clone(),
        params.clone(),
        key.binding().encoded(),
        key.vk().to_bytes(),
        &original,
        signature_read_config(&original),
        Some(&cancelled),
    )
    .err()
    .unwrap();
    assert!(error.is_cancelled());
    let mut invalid = witness();
    invalid.signature[1] = [0; 4];
    assert!(matches!(
        installed.prove(&[invalid], common::recovery(118), ProverConfig::default()),
        Err(QSignatureError::Signature)
    ));
    // The recovery factory is reached only after actual reconstruction and witness
    // assignment. Cancel there, then reuse this immutable owner successfully.
    use rand_chacha::rand_core::SeedableRng as _;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let after_rebuild = iroha_pasta::CancellationToken::new();
    let signal = after_rebuild.clone();
    let callbacks = Arc::new(AtomicUsize::new(0));
    let observed = callbacks.clone();
    let randomness = iroha_plonk::ProverRandomness::recovery(move |_: &[u8; 32]| {
        observed.fetch_add(1, Ordering::SeqCst);
        signal.cancel();
        Ok::<_, ()>(rand_chacha::ChaCha20Rng::from_seed([119; 32]))
    });
    let error = installed
        .prove(
            &[witness()],
            randomness,
            ProverConfig {
                cancellation: Some(&after_rebuild),
                ..ProverConfig::default()
            },
        )
        .unwrap_err();
    assert!(error.is_cancelled());
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    let proof = installed
        .prove(&[witness()], common::recovery(119), ProverConfig::default())
        .unwrap();
    assert_eq!(proof.instances, public);
    assert_eq!(proof.bytes, direct);
    let claim = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &proof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    claim.decide(&params, MemoryBudget::DEFAULT).unwrap();
    for index in [0, 1, 5, 9] {
        let mut wrong = public.clone();
        wrong[0][index] += Fq::ONE;
        assert!(
            accumulate_generator(
                &params,
                key.binding(),
                key.vk(),
                &wrong,
                &proof.bytes,
                MemoryBudget::DEFAULT
            )
            .is_err()
        );
    }
    eprintln!("signature native proof{}B", proof.bytes.len());
}

fn signature_read_config(original: &[u8]) -> ReadConfig {
    ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}

#[test]
#[ignore = "optimized actual native original-key admission component"]
fn installed_signature_originals_reject_bounds_keys_and_slot_source() {
    use iroha_plonk::keys::pk::artifact::Error as ArtifactError;
    let c = circuit(witness(), VerifyMode::Hard, true);
    let params = iroha_plonk::pcs::ipa::PinnedParams::<iroha_pasta::Ep>::derive(16).unwrap();
    let mut key_config = KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec());
    key_config.compress_selectors = false;
    let key = keygen_pk_v2(&params, &c, &key_config).unwrap();
    let factory = c.plan().source_circuit().unwrap();
    let (binding, verifier) =
        iroha_plonk::keys::keygen_vk_with_binding_v2(&params, &factory, &key_config).unwrap();
    assert_eq!(&binding, key.binding());
    assert_eq!(verifier.to_bytes(), key.vk().to_bytes());
    let original = key.artifact_bytes_v2().unwrap();
    let config = signature_read_config(&original);
    let mount = |bytes: &[u8], selected: ReadConfig| {
        QSignatureProver::from_original_artifact(
            c.plan().clone(),
            params.clone(),
            key.binding().encoded(),
            key.vk().to_bytes(),
            bytes,
            selected,
        )
    };
    let mut bounded = config;
    bounded.maximum_bytes -= 1;
    assert!(matches!(
        mount(&original, bounded),
        Err(QSignatureError::Artifact(ArtifactError::Length))
    ));
    bounded = config;
    bounded.maximum_rows -= 1;
    assert!(matches!(
        mount(&original, bounded),
        Err(QSignatureError::Artifact(ArtifactError::Length))
    ));
    assert!(mount(&original[..original.len() - 1], config).is_err());
    let mut corrupt = original.clone();
    corrupt[0] ^= 1;
    assert!(matches!(
        mount(&corrupt, config),
        Err(QSignatureError::Artifact(ArtifactError::Encoding))
    ));
    corrupt = original.clone();
    corrupt[8] ^= 1;
    assert!(matches!(
        mount(&corrupt, config),
        Err(QSignatureError::Artifact(ArtifactError::Encoding))
    ));
    corrupt = original.clone();
    let scalar_start = 44 + key.vk().to_bytes().len() + 32;
    corrupt[scalar_start..scalar_start + 32].fill(0xff);
    assert!(matches!(
        mount(&corrupt, config),
        Err(QSignatureError::Artifact(ArtifactError::Encoding))
    ));
    corrupt = original.clone();
    corrupt[44 + key.vk().to_bytes().len()] ^= 1;
    assert!(matches!(
        mount(&corrupt, config),
        Err(QSignatureError::Artifact(ArtifactError::Source))
    ));
    let oversized_descriptor = vec![0; (1 << 20) + 1];
    assert!(matches!(
        QSignatureProver::from_original_artifact(
            c.plan().clone(),
            params.clone(),
            &oversized_descriptor,
            key.vk().to_bytes(),
            &original,
            config
        ),
        Err(QSignatureError::Artifact(ArtifactError::Length))
    ));
    let oversized_vk = vec![0; (1 << 18) + 1];
    assert!(matches!(
        QSignatureProver::from_original_artifact(
            c.plan().clone(),
            params.clone(),
            key.binding().encoded(),
            &oversized_vk,
            &original,
            config
        ),
        Err(QSignatureError::Artifact(ArtifactError::Length))
    ));
    let mut wrong_profile =
        iroha_plonk::cs::CircuitDescriptorV2::decode(key.binding().encoded()).unwrap();
    wrong_profile.instance_types[0] = iroha_plonk::cs::InstanceType::Field;
    assert!(matches!(
        QSignatureProver::from_original_artifact(
            c.plan().clone(),
            params.clone(),
            &wrong_profile.encode().unwrap(),
            key.vk().to_bytes(),
            &original,
            config
        ),
        Err(QSignatureError::Profile)
    ));
    let mut wrong_vk = key.vk().to_bytes().to_vec();
    wrong_vk[0] ^= 1;
    assert!(
        QSignatureProver::from_original_artifact(
            c.plan().clone(),
            params.clone(),
            key.binding().encoded(),
            &wrong_vk,
            &original,
            config
        )
        .is_err()
    );
    assert!(matches!(
        QSignatureProver::from_original_artifact(
            c.plan().clone(),
            iroha_plonk::pcs::ipa::PinnedParams::derive(15).unwrap(),
            key.binding().encoded(),
            key.vk().to_bytes(),
            &original,
            config
        ),
        Err(QSignatureError::Parameters)
    ));
    for plan in [
        circuit(witness(), VerifyMode::Soft, true).plan().clone(),
        circuit(witness(), VerifyMode::Hard, false).plan().clone(),
        QSignaturePlan::new(vec![SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Fixed(Affine::GENERATOR),
        }])
        .unwrap(),
        QSignaturePlan::new(vec![
            SignatureSlot {
                mode: VerifyMode::Hard,
                key: c.plan().slots()[0].key,
            };
            2
        ])
        .unwrap(),
    ] {
        assert!(
            QSignatureProver::from_original_artifact(
                plan,
                params.clone(),
                key.binding().encoded(),
                key.vk().to_bytes(),
                &original,
                config
            )
            .is_err()
        );
    }
    let installed = mount(&original, config).unwrap();
    let mut wrong_key = witness();
    wrong_key.key = [Affine::GENERATOR.x, Affine::GENERATOR.y];
    assert!(matches!(
        installed.prove(&[wrong_key], common::recovery(120), ProverConfig::default()),
        Err(QSignatureError::KeyBinding)
    ));
}

#[test]
#[ignore = "optimized actual native total soft signature-Q proof component"]
fn installed_signature_originals_prove_total_soft_failures() {
    let c = circuit(witness(), VerifyMode::Soft, false);
    let params = iroha_plonk::pcs::ipa::PinnedParams::<iroha_pasta::Ep>::derive(16).unwrap();
    let mut key_config = KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec());
    key_config.compress_selectors = false;
    let key = keygen_pk_v2(&params, &c, &key_config).unwrap();
    let original = key.artifact_bytes_v2().unwrap();
    let installed = QSignatureProver::from_original_artifact(
        c.plan().clone(),
        params,
        key.binding().encoded(),
        key.vk().to_bytes(),
        &original,
        signature_read_config(&original),
    )
    .unwrap();
    let mut invalid = witness();
    invalid.signature[1] = [0; 4];
    let proof = installed
        .prove(&[invalid], common::recovery(121), ProverConfig::default())
        .unwrap();
    assert_eq!(
        proof.instances,
        circuit(invalid, VerifyMode::Soft, false)
            .instances(&[false])
            .unwrap()
    );
    assert_eq!(proof.instances[0][9], Fq::ZERO);
    let claim = accumulate_generator(
        installed.params(),
        installed.binding(),
        installed.verifying_key(),
        &proof.instances,
        &proof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    claim
        .decide(installed.params(), MemoryBudget::DEFAULT)
        .unwrap();
    let mut forged = proof.instances.clone();
    forged[0][9] = Fq::ONE;
    assert!(
        accumulate_generator(
            installed.params(),
            installed.binding(),
            installed.verifying_key(),
            &forged,
            &proof.bytes,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
}
