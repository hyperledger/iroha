//! Test-only canonical public-witness inverse for Load signature Q1/Q2.
//!
//! The syntax inverse does not authorize a signature. The separate validation
//! helper uses the unchanged native low-S/fixed-key policy and compares the
//! derived public frame before proof entry. Ordinary controls generate no PLONK
//! parameters, keys or proofs; the explicitly ignored parity test does.

use ff::PrimeField;
use iroha_plonk_gadgets::p256::native::{self, HALF_N, ORDER};

use super::*;
use crate::q_signature::{SLOT_WORDS, SignatureSlot};

type Frame = Vec<Vec<[u8; 32]>>;

fn frame(instances: &[Vec<Fq>]) -> Frame {
    instances
        .iter()
        .map(|column| column.iter().map(PrimeField::to_repr).collect())
        .collect()
}

fn decode_signatures(public: &Frame, slots: usize) -> Result<Vec<SignatureWitness>, &'static str> {
    if !matches!(slots, 1 | 2) || public.len() != 1 || public[0].len() != SLOT_WORDS * slots {
        return Err("Load signature shape");
    }
    let values = public[0]
        .iter()
        .map(|word| Fq::from_repr(*word).into_option().ok_or("noncanonical Fq"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut witnesses = Vec::with_capacity(slots);
    for (words, raw) in values
        .chunks_exact(SLOT_WORDS)
        .zip(public[0].chunks_exact(SLOT_WORDS))
    {
        let digest = Fp::from_repr(words[0].to_repr())
            .into_option()
            .ok_or("noncanonical Fp digest")?;
        if words[9] != Fq::ZERO && words[9] != Fq::ONE {
            return Err("nonboolean verdict");
        }
        let mut integers = [[0_u64; 4]; 4];
        for (integer, pair) in integers.iter_mut().zip(raw[1..9].chunks_exact(2)) {
            for (half, word) in pair.iter().enumerate() {
                if word[16..].iter().any(|byte| *byte != 0) {
                    return Err("limb above 128 bits");
                }
                integer[half * 2] = u64::from_le_bytes(word[..8].try_into().unwrap());
                integer[half * 2 + 1] = u64::from_le_bytes(word[8..16].try_into().unwrap());
            }
        }
        witnesses.push(SignatureWitness {
            digest,
            key: [integers[0], integers[1]],
            signature: [integers[2], integers[3]],
        });
    }
    Ok(witnesses)
}

fn validate_signatures(
    plan: &QSignaturePlan,
    public: &Frame,
) -> Result<Vec<SignatureWitness>, QSignatureError> {
    let witnesses = decode_signatures(public, plan.slots().len())
        .map_err(|_| QSignatureError::Layout(LayoutError::Synthesis))?;
    if frame(&plan.native_instances(&witnesses)?) != *public {
        return Err(QSignatureError::Layout(LayoutError::Synthesis));
    }
    Ok(witnesses)
}

fn assert_same_witnesses(actual: &[SignatureWitness], expected: &[SignatureWitness]) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(actual.digest, expected.digest);
        assert_eq!(actual.key, expected.key);
        assert_eq!(actual.signature, expected.signature);
    }
}

// Existing tests/q_signature.rs::witness recipe, parameterized only by the
// digest/secret/nonce so Q2's ordered variable and fixed slots are distinct.
fn signature(digest: u64, secret: u64, nonce: u64) -> SignatureWitness {
    let digest = Fp::from(digest);
    let hash = sha256_of_digest(&digest);
    let message = core::array::from_fn(|i| {
        u64::from_be_bytes(hash[(3 - i) * 8..(4 - i) * 8].try_into().unwrap())
    });
    let secret = [secret, 0, 0, 0];
    let nonce = [nonce, 0, 0, 0];
    let key = native::mul(&Affine::GENERATOR, &secret).unwrap();
    let r = ORDER.reduce_once(&native::mul(&Affine::GENERATOR, &nonce).unwrap().x);
    let mut s = ORDER.mul(
        &ORDER.inverse(&nonce),
        &ORDER.add(&ORDER.reduce_once(&message), &ORDER.mul(&r, &secret)),
    );
    if native::words_cmp(&s, &HALF_N).is_gt() {
        s = ORDER.neg(&s);
    }
    assert!(verify_prehashed(&message, &r, &s, &key));
    SignatureWitness {
        digest,
        key: [key.x, key.y],
        signature: [r, s],
    }
}

fn load_cases() -> [(QSignaturePlan, Vec<SignatureWitness>); 2] {
    // Same slot policies as CoreZk producer_inventory/q.rs::signature_plans(Load).
    let own = signature(123, 17, 19);
    let root = signature(456, 23, 29);
    let variable = SignatureSlot {
        mode: VerifyMode::Hard,
        key: SignatureKey::Variable,
    };
    let fixed = SignatureSlot {
        mode: VerifyMode::Hard,
        key: SignatureKey::Fixed(Affine {
            x: root.key[0],
            y: root.key[1],
        }),
    };
    [
        (QSignaturePlan::new(vec![variable]).unwrap(), vec![own]),
        (
            QSignaturePlan::new(vec![variable, fixed]).unwrap(),
            vec![own, root],
        ),
    ]
}

#[test]
fn load_signature_public_inverse_matches_all_typed_fields_and_native_instances() {
    for (plan, witnesses) in load_cases() {
        let public = frame(&plan.native_instances(&witnesses).unwrap());
        let restored = validate_signatures(&plan, &public).unwrap();
        assert_same_witnesses(&restored, &witnesses);
        assert_eq!(
            plan.native_instances(&restored).unwrap(),
            plan.native_instances(&witnesses).unwrap()
        );
        let actual = QSignatureCircuit::new(plan.clone(), restored).unwrap();
        assert!(actual.known);
        assert_eq!(actual.plan.slots(), plan.slots());
        assert_same_witnesses(&actual.witnesses, &witnesses);
    }
}

#[test]
fn load_signature_inverse_rejects_shape_and_noncanonical_words() {
    let (plan, witnesses) = load_cases().into_iter().nth(1).unwrap();
    let original = frame(&plan.native_instances(&witnesses).unwrap());
    for slots in [0, 1, 3, usize::MAX] {
        assert_eq!(
            decode_signatures(&original, slots).unwrap_err(),
            "Load signature shape"
        );
    }
    let mut public = original.clone();
    public.push(vec![]);
    assert_eq!(
        decode_signatures(&public, 2).unwrap_err(),
        "Load signature shape"
    );
    let mut public = original.clone();
    public[0].pop();
    assert_eq!(
        decode_signatures(&public, 2).unwrap_err(),
        "Load signature shape"
    );
    for row in 0..20 {
        let mut public = original.clone();
        public[0][row] = [255; 32];
        assert_eq!(
            decode_signatures(&public, 2).unwrap_err(),
            "noncanonical Fq"
        );
    }
}

#[test]
fn load_signature_inverse_checks_every_low_and_high_u128_limb() {
    let (plan, witnesses) = load_cases().into_iter().nth(1).unwrap();
    let original = frame(&plan.native_instances(&witnesses).unwrap());
    for slot in 0..2 {
        for limb in 1..9 {
            let mut public = original.clone();
            public[0][slot * SLOT_WORDS + limb][16] = 1;
            assert_eq!(
                decode_signatures(&public, 2).unwrap_err(),
                "limb above 128 bits"
            );
        }
    }
    // Raw maximum unsigned values must roundtrip, without reducing modulo P/N.
    let data = SignatureWitness {
        digest: Fp::from(7),
        key: [[u64::MAX; 4]; 2],
        signature: [[u64::MAX; 4]; 2],
    };
    let soft = QSignaturePlan::new(vec![SignatureSlot {
        mode: VerifyMode::Soft,
        key: SignatureKey::Variable,
    }])
    .unwrap();
    let public = frame(&soft.native_instances(&[data]).unwrap());
    assert_eq!(public[0][9], Fq::ZERO.to_repr());
    assert_same_witnesses(&validate_signatures(&soft, &public).unwrap(), &[data]);
}

#[test]
fn load_signature_inverse_rejects_fp_alias_and_proposed_verdicts() {
    let (plan, witnesses) = load_cases().into_iter().next().unwrap();
    let original = frame(&plan.native_instances(&witnesses).unwrap());
    let mut non_fp = (-Fp::ONE).to_repr();
    for byte in &mut non_fp {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
    let mut public = original.clone();
    public[0][0] = non_fp;
    assert_eq!(
        decode_signatures(&public, 1).unwrap_err(),
        "noncanonical Fp digest"
    );
    let mut public = original.clone();
    public[0][9] = Fq::from(2).to_repr();
    assert_eq!(
        decode_signatures(&public, 1).unwrap_err(),
        "nonboolean verdict"
    );
    let mut public = original;
    public[0][9] = Fq::ZERO.to_repr();
    assert!(decode_signatures(&public, 1).is_ok());
    assert!(matches!(
        validate_signatures(&plan, &public),
        Err(QSignatureError::Layout(_))
    ));
}

#[test]
fn load_signature_inverse_enforces_fixed_key_and_low_s_native_policy() {
    let (plan, witnesses) = load_cases().into_iter().nth(1).unwrap();
    let mut wrong = witnesses.clone();
    wrong[1] = signature(456, 31, 37);
    // Export DATA with true bits; neither this exporter nor the inverse verifies it.
    let public = frame(
        &QSignatureCircuit::new(plan.clone(), wrong)
            .unwrap()
            .instances(&[true, true])
            .unwrap(),
    );
    assert!(decode_signatures(&public, 2).is_ok());
    assert!(matches!(
        validate_signatures(&plan, &public),
        Err(QSignatureError::KeyBinding)
    ));
    let mut high_s = witnesses;
    high_s[0].signature[1] = ORDER.neg(&high_s[0].signature[1]);
    let public = frame(
        &QSignatureCircuit::new(plan.clone(), high_s)
            .unwrap()
            .instances(&[true, true])
            .unwrap(),
    );
    assert!(decode_signatures(&public, 2).is_ok());
    assert!(matches!(
        validate_signatures(&plan, &public),
        Err(QSignatureError::Signature)
    ));
}

#[test]
fn load_signature_inverse_binds_digest_slot_order_and_original_signature() {
    let (plan, witnesses) = load_cases().into_iter().nth(1).unwrap();
    let original = frame(&plan.native_instances(&witnesses).unwrap());
    for row in [0, 5, 7, 10, 15, 17] {
        let mut public = original.clone();
        public[0][row][0] ^= 1;
        assert!(
            validate_signatures(&plan, &public).is_err(),
            "changed row {row}"
        );
    }
    let mut public = original;
    public[0].rotate_left(SLOT_WORDS);
    assert!(matches!(
        validate_signatures(&plan, &public),
        Err(QSignatureError::KeyBinding)
    ));
}

#[test]
#[ignore = "two Load signature profiles: two k16 keygens/imports and four proofs; explicit resource handoff"]
fn genuine_load_signature_public_inverse_native_proof_parity() {
    use iroha_plonk::keys::{KeygenConfigV2, keygen_pk_from_vk_v2, keygen_pk_v2};
    for (plan, witnesses) in load_cases() {
        // A new owner makes each measured admission's public-column cache cold.
        // Parameter derivation and fixture keygen are outside the measured phases.
        let params = PinnedParams::<Ep>::derive(16).unwrap();
        let public = frame(&plan.native_instances(&witnesses).unwrap());
        let restored = validate_signatures(&plan, &public).unwrap();
        assert_same_witnesses(&restored, &witnesses);
        // Strict original import keeps policy/source authority independent of
        // the inverse; no raw-key/unchecked public witness constructor is added.
        let mut config = KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec());
        config.coset_cache = CosetCachePolicy::OnDemand;
        let key = keygen_pk_v2(&params, &plan.source_circuit().unwrap(), &config).unwrap();
        // Optional output belongs only to this explicitly ignored diagnostic.
        // It contains freshly synthesized public columns and reference VK points,
        // never advice, witnesses, signing material or an admission capability.
        if let Some(directory) = std::env::var_os("IROHA_PUBLIC_COLUMN_FIXTURE_DIR") {
            use group::GroupEncoding;
            use sha2::Digest;
            use std::io::Write;
            let columns: Vec<Vec<[u8; 32]>> = key
                .fixed_values()
                .iter()
                .chain(key.permutation_values())
                .map(|column| column.iter().map(PrimeField::to_repr).collect())
                .collect();
            let points: Vec<[u8; 32]> = key
                .vk()
                .fixed_commitments()
                .iter()
                .chain(key.vk().permutation_commitments())
                .map(GroupEncoding::to_bytes)
                .collect();
            let encoded = norito::to_bytes(&(16_u32, points, columns)).unwrap();
            let path = std::path::PathBuf::from(directory)
                .join(format!("load-signature-{}.norito", plan.slots().len()));
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            output.write_all(&encoded).unwrap();
            output.sync_all().unwrap();
            println!(
                "PUBLIC_COLUMN_FIXTURE path={} sha256={:x}",
                path.display(),
                sha2::Sha256::digest(&encoded)
            );
        }
        let original = key.artifact_bytes_v2().unwrap();
        let original_bytes = original.len();
        let table_bytes =
            (key.fixed_values().len() + key.permutation_values().len()) * key.binding().n() * 32;
        let descriptor = key.binding().encoded().to_vec();
        let vk = key.vk().to_bytes().to_vec();
        assert_eq!(original_bytes, 108 + vk.len());
        drop(key);
        let started = std::time::Instant::now();
        let owner = QSignatureProver::from_original_artifact(
            plan.clone(),
            params.clone(),
            &descriptor,
            &vk,
            &original,
            ReadConfig {
                maximum_bytes: original.len(),
                maximum_rows: 1 << 16,
                coset_cache: CosetCachePolicy::OnDemand,
                msm_budget: iroha_pasta::msm::MemoryBudget::DEFAULT,
            },
        )
        .unwrap();
        let admission_ms = started.elapsed().as_millis();
        let metadata = owner.into_metadata();
        assert_eq!(metadata.binding().encoded(), descriptor);
        assert_eq!(metadata.verifying_key().to_bytes(), vk);
        let started = std::time::Instant::now();
        let reconstructed = keygen_pk_from_vk_v2(
            &params,
            &plan.source_circuit().unwrap(),
            &metadata.view(),
            CosetCachePolicy::OnDemand,
        )
        .unwrap();
        let reconstruction_ms = started.elapsed().as_millis();
        assert_eq!(reconstructed.artifact_bytes_v2().unwrap(), original);
        assert!(!reconstructed.has_coset_cache());
        drop(reconstructed);
        drop(original);
        let owner =
            QSignatureProverView::from_source_bound(&plan, &params, metadata.view()).unwrap();
        // Both pre-cut reconstruction/validation paths have now finished.
        crate::proof_entry_probe::assert_owner_cancellation(
            |token| {
                owner.prove(
                    &witnesses,
                    ProverRandomness::hedged(),
                    ProverConfig {
                        cancellation: Some(token),
                        ..ProverConfig::default()
                    },
                )
            },
            |error| error.is_cancelled(),
        );

        let refused = crate::proof_entry_probe::Guard::new(None);
        let mut invalid = witnesses.clone();
        invalid[0].signature[1] = [0; 4];
        assert!(matches!(
            owner.prove(
                &invalid,
                ProverRandomness::hedged(),
                ProverConfig::default()
            ),
            Err(QSignatureError::Signature)
        ));
        assert_eq!(
            refused.entries(),
            0,
            "invalid signature never enters prover"
        );
        drop(refused);

        let entries = crate::proof_entry_probe::Guard::new(None);

        let started = std::time::Instant::now();
        let first = owner
            .prove(
                &witnesses,
                ProverRandomness::hedged(),
                ProverConfig::default(),
            )
            .unwrap();
        let first_prove_ms = started.elapsed().as_millis();
        let started = std::time::Instant::now();
        let second = owner
            .prove(
                &restored,
                ProverRandomness::hedged(),
                ProverConfig::default(),
            )
            .unwrap();
        let second_prove_ms = started.elapsed().as_millis();

        assert_eq!(entries.entries(), 2);
        assert_ne!(
            first.bytes, second.bytes,
            "fresh proofs use independent OS draws"
        );
        assert_eq!(first.instances, second.instances);
        assert_eq!(frame(&first.instances), public);
        let started = std::time::Instant::now();
        for proof in [&first, &second] {
            iroha_plonk::verify_full(
                owner.params(),
                owner.binding(),
                owner.verifying_key(),
                &proof.instances,
                &proof.bytes,
                iroha_pasta::msm::MemoryBudget::DEFAULT,
            )
            .unwrap();
        }
        let verify_pair_ms = started.elapsed().as_millis();
        let retained = first.bytes.clone();
        for _ in 0..2 {
            iroha_plonk::verify_full(
                owner.params(),
                owner.binding(),
                owner.verifying_key(),
                &first.instances,
                &retained,
                iroha_pasta::msm::MemoryBudget::DEFAULT,
            )
            .unwrap();
        }
        assert_eq!(
            retained, first.bytes,
            "retained original replay preserves exact bytes"
        );
        assert_eq!(
            entries.entries(),
            2,
            "verifier replay never re-enters a producer"
        );

        println!(
            "COMPACT_HOST_Q_SIGNATURE k=16 slots={} original_bytes={} reconstructed_table_bytes={} cold_metadata_admission_ms={} source_bound_reconstruction_ms={} native_prove_and_self_verify_ms={} repeat_native_prove_and_self_verify_ms={} explicit_verify_pair_ms={}",
            plan.slots().len(),
            original_bytes,
            table_bytes,
            admission_ms,
            reconstruction_ms,
            first_prove_ms,
            second_prove_ms,
            verify_pair_ms,
        );
    }
    println!(
        "LOAD_SIGNATURE_PUBLIC_INVERSE keygens=2 strict_imports=2 proofs=4 complete_native_verification=true qualification=false"
    );
}
