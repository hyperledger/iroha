//! Bounded original frames, fixed native identities and complete catalog regressions.

use super::*;
use iroha_data_model::isi::{
    InstructionBox,
    kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
};

#[test]
#[ignore = "genuine complete k12/k16 native verifier inventory; run optimized"]
fn genuine_signed_complete_inventory_mounts_and_rejects_substituted_originals() {
    let (pack, installation) = engineering_fixture::signed_inventory();
    let original = pack.to_canonical_bytes().unwrap();
    let installed = InstalledVerifierPackV1::load(&original, installation).unwrap();
    assert_eq!(installed.original(), original);
    assert_eq!(installed.originals(), &pack);
    assert_eq!(
        installed.verifier().scheme().scheme_id(),
        installation.scheme_id
    );
    for pin in [[0; 32], [0x52; 32]] {
        assert!(
            InstalledVerifierPackV1::load(
                &original,
                InstallationV1 {
                    manifest_digest: pin,
                    ..installation
                }
            )
            .is_err()
        );
    }
    for changed_member in 0..7 {
        let mut changed = pack.clone();
        let member = match changed_member {
            0 => &mut changed.scheme,
            1 => &mut changed.signer_certificate,
            2 => &mut changed.manifest,
            3 => &mut changed.steps[0].artifact.descriptor,
            4 => &mut changed.steps[0].artifact.verifying_key,
            5 => &mut changed.lineage.descriptor,
            _ => &mut changed.lineage.verifying_key,
        };
        *member.last_mut().unwrap() ^= 1;
        assert!(
            InstalledVerifierPackV1::load(&changed.to_canonical_bytes().unwrap(), installation)
                .is_err(),
            "substituted authority/native original {changed_member}"
        );
    }
    let mut changed = pack.clone();
    changed.producer_catalog_digest[0] ^= 1;
    assert!(
        InstalledVerifierPackV1::load(&changed.to_canonical_bytes().unwrap(), installation)
            .is_err()
    );
    assert!(
        installed
            .authenticate_producer_inventory(b"engineering-verifier-only")
            .is_err()
    );
}

#[test]
#[ignore = "genuine complete k12/k16 native verifier inventory; run optimized"]
fn verifier_admission_mounts_an_earlier_producer_profile_and_keeps_every_other_binding() {
    let earlier = artifact_digest(b"native-profile", b"earlier producer generation");
    let (pack, installation) = engineering_fixture::signed_inventory_with_profile(earlier);
    let original = pack.to_canonical_bytes().unwrap();
    // Producer admission stays bound to this source's compiled profile.
    assert!(matches!(
        InstalledVerifierPackV1::load(&original, installation),
        Err(Error::RuntimeBinding)
    ));
    // Verifier admission yields only the verifier; no producer inventory can follow from it.
    let verifier = InstalledVerifierPackV1::load_verifier(&original, installation).unwrap();
    assert_eq!(verifier.scheme().scheme_id(), installation.scheme_id);
    assert_eq!(verifier.manifest_digest(), installation.manifest_digest);
    for changed_member in 0..7 {
        let mut changed = pack.clone();
        let member = match changed_member {
            0 => &mut changed.scheme,
            1 => &mut changed.signer_certificate,
            2 => &mut changed.manifest,
            3 => &mut changed.steps[0].artifact.descriptor,
            4 => &mut changed.steps[0].artifact.verifying_key,
            5 => &mut changed.lineage.descriptor,
            _ => &mut changed.lineage.verifying_key,
        };
        *member.last_mut().unwrap() ^= 1;
        assert!(
            InstalledVerifierPackV1::load_verifier(
                &changed.to_canonical_bytes().unwrap(),
                installation
            )
            .is_err(),
            "substituted authority/native original {changed_member}"
        );
    }
    let mut changed = pack.clone();
    changed.producer_catalog_digest[0] ^= 1;
    assert!(
        InstalledVerifierPackV1::load_verifier(
            &changed.to_canonical_bytes().unwrap(),
            installation
        )
        .is_err()
    );
    // A coherently signed scheme and manifest naming a profile the inventory was not built
    // with is refused by both admissions.
    let compiled = artifact_digest(b"native-profile", &native_profile_transcript_v1().unwrap());
    for named in [
        compiled,
        artifact_digest(b"native-profile", b"another generation"),
    ] {
        let (resigned, resigned_installation) =
            engineering_fixture::resigned_with_profile(&pack, installation, named);
        assert_ne!(resigned_installation.scheme_id, installation.scheme_id);
        let bytes = resigned.to_canonical_bytes().unwrap();
        assert!(matches!(
            InstalledVerifierPackV1::load_verifier(&bytes, resigned_installation),
            Err(Error::RuntimeBinding)
        ));
        assert!(matches!(
            InstalledVerifierPackV1::load(&bytes, resigned_installation),
            Err(Error::RuntimeBinding)
        ));
    }
    // A pack built from this source mounts the same verifier under both admissions.
    let (current, current_installation) = engineering_fixture::signed_inventory();
    let bytes = current.to_canonical_bytes().unwrap();
    let installed = InstalledVerifierPackV1::load(&bytes, current_installation).unwrap();
    let verifier = InstalledVerifierPackV1::load_verifier(&bytes, current_installation).unwrap();
    assert_eq!(verifier.scheme(), installed.verifier().scheme());
    assert_eq!(
        verifier.manifest_digest(),
        installed.verifier().manifest_digest()
    );
}

/// The exact installed pack original and its independently recorded installation pins.
fn retained_installation() -> (Vec<u8>, InstallationV1) {
    let original = std::fs::read(std::env::var("KAGEMUSHA_INSTALLED_PACK").unwrap()).unwrap();
    let pin = |name: &str| -> [u8; 32] {
        hex::decode(std::env::var(name).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    (
        original,
        InstallationV1 {
            scheme_id: pin("KAGEMUSHA_INSTALLED_SCHEME"),
            manifest_digest: pin("KAGEMUSHA_INSTALLED_MANIFEST"),
        },
    )
}

#[test]
#[ignore = "retained installed pack: KAGEMUSHA_INSTALLED_PACK=<path> KAGEMUSHA_INSTALLED_SCHEME=<hex> KAGEMUSHA_INSTALLED_MANIFEST=<hex>"]
fn retained_installed_pack_mounts_for_ledger_verification() {
    let (original, installation) = retained_installation();
    let verifier = InstalledVerifierPackV1::load_verifier(&original, installation).unwrap();
    assert_eq!(verifier.manifest_digest(), installation.manifest_digest);
    let pack = VerifierPackV1::decode_canonical(&original).unwrap();
    let scheme =
        KagemushaWalletSchemeV1::decode_canonical(&pack.scheme, &installation.scheme_id).unwrap();
    let named = KagemushaWalletArtifactManifestV1::decode_canonical(&pack.manifest, &scheme)
        .unwrap()
        .body
        .native_profile_digest;
    let compiled = artifact_digest(b"native-profile", &native_profile_transcript_v1().unwrap());
    let producer = InstalledVerifierPackV1::load(&original, installation);
    eprintln!(
        "RETAINED_PACK_VERIFIER_ADMITTED profile={} compiled={} producer_admission={}",
        hex::encode(named),
        hex::encode(compiled),
        producer.is_ok()
    );
    if named != compiled {
        assert!(matches!(producer, Err(Error::RuntimeBinding)));
    }
}

#[test]
#[ignore = "retained ledger history: the KAGEMUSHA_INSTALLED_* pins plus KAGEMUSHA_HISTORICAL_INSTRUCTIONS=<directory of exact committed instruction originals>"]
fn retained_ledger_history_verifies_under_verifier_admission() {
    let (original, installation) = retained_installation();
    let verifier = InstalledVerifierPackV1::load_verifier(&original, installation).unwrap();
    let mut paths: Vec<_> =
        std::fs::read_dir(std::env::var("KAGEMUSHA_HISTORICAL_INSTRUCTIONS").unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
    paths.sort();
    let (mut installs, mut activations) = (0, 0);
    for path in paths {
        let framed = std::fs::read(&path).unwrap();
        // A committed transaction carries each instruction as its exact registry frame.
        let boxed: InstructionBox = norito::decode_canonical_with_limits(
            &framed,
            norito::canonical_decode_limits(framed.len()),
        )
        .unwrap();
        let instruction = boxed
            .as_any()
            .downcast_ref::<KagemushaWalletLedgerV1>()
            .unwrap();
        assert_eq!(instruction.scheme, installation.scheme_id);
        match &instruction.action {
            KagemushaWalletLedgerActionV1::InstallVerifierPack {
                manifest_digest,
                pack,
                ..
            } => {
                assert_eq!(*manifest_digest, installation.manifest_digest);
                assert_eq!(*pack, original);
                installs += 1;
            }
            KagemushaWalletLedgerActionV1::Activate(bytes) => {
                // The ledger's order: exact activation authority, then the native Bootstrap
                // proof under the mounted verifier.
                let activation =
                    KagemushaWalletActivationV1::decode_canonical(bytes, &instruction.scheme)
                        .unwrap();
                activation.verify(verifier.scheme()).unwrap();
                verifier
                    .verify_package_proofs(&activation.bootstrap, Default::default())
                    .unwrap();
                activations += 1;
                eprintln!("HISTORICAL_ACTIVATION_VERIFIED {}", path.display());
            }
            _ => {}
        }
    }
    eprintln!("RETAINED_LEDGER_HISTORY_VERIFIED installs={installs} activations={activations}");
    assert_eq!(installs, 1);
    assert!(activations > 0);
}

fn kind(tag: u8) -> KagemushaWalletOperationKindV1 {
    *KagemushaWalletOperationKindV1::ALL
        .iter()
        .find(|kind| kind.tag() == tag)
        .unwrap()
}

fn structural_pack() -> VerifierPackV1 {
    // Deliberately invalid authority/proof bytes. Only bounded canonical carrier tests
    // use this fixture; it cannot construct an InstalledVerifierPackV1 or native verdict.
    VerifierPackV1 {
        version: 1,
        scheme: vec![1],
        signer_certificate: vec![2],
        manifest: vec![3],
        allowlist: vec![4],
        steps: SIGMA_CATALOG_V1
            .iter()
            .map(|(tag, mask)| StepOriginalV1 {
                kind: kind(*tag),
                enabled_controls: *mask,
                artifact: ArtifactOriginalV1 {
                    descriptor: vec![*tag],
                    verifying_key: vec![*mask as u8 + 1],
                },
            })
            .collect(),
        lineage: ArtifactOriginalV1 {
            descriptor: vec![17],
            verifying_key: vec![18],
        },
        producer_catalog_digest: [19; 32],
    }
}

#[test]
fn canonical_carrier_retains_every_original_and_rejects_trailing_bytes() {
    let pack = structural_pack();
    let original = pack.to_canonical_bytes().unwrap();
    assert_eq!(VerifierPackV1::decode_canonical(&original).unwrap(), pack);
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(VerifierPackV1::decode_canonical(&trailing).is_err());
    let mut changed_version = pack.clone();
    changed_version.version = 2;
    assert!(changed_version.to_canonical_bytes().is_err());
    let mut missing_producers = pack.clone();
    missing_producers.producer_catalog_digest = [0; 32];
    assert!(missing_producers.to_canonical_bytes().is_err());
    assert_eq!(
        InstalledVerifierPackV1::load(
            &original,
            InstallationV1 {
                scheme_id: [1; 32],
                manifest_digest: [2; 32],
            }
        )
        .err(),
        Some(Error::Authority)
    );
    assert_eq!(pack.runtime_bindings(), Err(Error::Inventory));
}

#[test]
fn full_catalog_rejects_missing_extra_reordered_and_undefined_selectors() {
    let pack = structural_pack();
    for missing in 0..SIGMA_CATALOG_V1.len() {
        let mut changed = pack.clone();
        changed.steps.remove(missing);
        assert_eq!(changed.inventory_bounds(), Err(Error::Inventory));
    }
    let mut extra = pack.clone();
    extra.steps.push(extra.steps[0].clone());
    assert_eq!(extra.inventory_bounds(), Err(Error::Inventory));
    for index in 0..SIGMA_CATALOG_V1.len() - 1 {
        let mut changed = pack.clone();
        changed.steps.swap(index, index + 1);
        assert_eq!(changed.inventory_bounds(), Err(Error::Inventory));
    }
    let mut mask = pack.clone();
    mask.steps[0].enabled_controls = 1;
    assert_eq!(mask.inventory_bounds(), Err(Error::Inventory));
    let mut receive = pack.clone();
    // Receive has one selector: its retired mask-1 key is no catalog member.
    receive.steps[6].enabled_controls = 1;
    assert_eq!(receive.inventory_bounds(), Err(Error::Inventory));
    assert!(
        KagemushaWalletOperationKindV1::ALL
            .iter()
            .all(|kind| SIGMA_CATALOG_V1.contains(&(kind.tag(), 0)))
    );
    assert_eq!(
        SIGMA_CATALOG_V1.iter().filter(|(tag, _)| *tag == 3).count(),
        4
    );
}

#[test]
fn all_resource_caps_apply_before_profile_or_authority_decode() {
    let mut total = 0;
    let empty = ArtifactOriginalV1 {
        descriptor: vec![],
        verifying_key: vec![1],
    };
    assert_eq!(artifact_bounds(&empty, &mut total), Err(Error::Inventory));
    let oversized = ArtifactOriginalV1 {
        descriptor: vec![0; DESCRIPTOR_MAX_BYTES_V1 + 1],
        verifying_key: vec![1],
    };
    assert_eq!(
        artifact_bounds(&oversized, &mut total),
        Err(Error::Inventory)
    );
    let oversized_key = ArtifactOriginalV1 {
        descriptor: vec![1],
        verifying_key: vec![0; VERIFYING_KEY_MAX_BYTES_V1 + 1],
    };
    assert_eq!(
        artifact_bounds(&oversized_key, &mut total),
        Err(Error::Inventory)
    );
    total = INVENTORY_MAX_BYTES_V1 - 1;
    assert_eq!(
        artifact_bounds(
            &ArtifactOriginalV1 {
                descriptor: vec![1],
                verifying_key: vec![1]
            },
            &mut total
        ),
        Err(Error::Inventory)
    );
    total = usize::MAX;
    assert_eq!(
        artifact_bounds(
            &ArtifactOriginalV1 {
                descriptor: vec![1],
                verifying_key: vec![1]
            },
            &mut total
        ),
        Err(Error::Inventory)
    );
    assert!(VerifierPackV1::decode_canonical(&vec![0; VERIFIER_PACK_MAX_BYTES_V1 + 1]).is_err());
    assert!(VerifierPackV1::decode_canonical(&[]).is_err());
    let mut pack = structural_pack();
    pack.manifest
        .resize(KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1 + 1, 0);
    assert_eq!(pack.bounds(), Err(Error::Inventory));
}

#[test]
fn independent_installation_is_nonzero_and_never_selected_from_pack() {
    let original = structural_pack().to_canonical_bytes().unwrap();
    for installation in [
        InstallationV1 {
            scheme_id: [0; 32],
            manifest_digest: [1; 32],
        },
        InstallationV1 {
            scheme_id: [1; 32],
            manifest_digest: [0; 32],
        },
    ] {
        assert_eq!(
            InstalledVerifierPackV1::load(&original, installation).err(),
            Some(Error::RuntimeBinding)
        );
    }
}

#[test]
fn native_protocol_preimages_bind_actual_curve_tables_and_params() {
    let eq = eq_protocol_transcript_v1().unwrap();
    let ep = ep_protocol_transcript_v1().unwrap();
    assert_ne!(eq, ep);
    assert_eq!(&eq[..5], &[1, 0, 1, 0, 1]);
    assert_eq!(&ep[..5], &[1, 0, 1, 0, 0]);
    assert_eq!(&eq[5..37], &CurveV1::Vesta.base_modulus());
    assert_eq!(&eq[37..69], &CurveV1::Vesta.scalar_modulus());
    for (curve, bytes) in [(CurveV1::Vesta, eq), (CurveV1::Pallas, ep)] {
        for k in 12..=16 {
            let params = pinned_params_digest(curve, k).unwrap();
            assert!(bytes.windows(params.len()).any(|window| window == params));
        }
        assert!(bytes.windows(8).any(|window| window == Domain::Proof.tag()));
        assert!(bytes.windows(8).any(|window| window == Domain::Fold.tag()));
    }
}

#[test]
fn native_profile_contains_fixed_typed_policies_and_all_decision_codes() {
    let sigma = policy(false).expect("fixed sigma policy");
    let omega = policy(true).expect("fixed omega policy");
    assert_eq!(sigma.curve, CurveV1::Vesta);
    assert_eq!(sigma.instance_lengths, vec![1]);
    assert_eq!(sigma.instance_types, vec![InstanceType::Bounded]);
    assert_eq!(omega.curve, CurveV1::Pallas);
    assert_eq!((omega.min_k, omega.max_k), (16, 16));
    assert_eq!(omega.instance_lengths, vec![1, 2, 16]);
    assert_eq!(
        omega.instance_types,
        vec![
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bounded
        ]
    );
    let profile = native_profile_transcript_v1().unwrap();
    assert_eq!(&profile[..6], &[1, 0, 11, 0, 0, 0]);
    let marker = b"kgwomg_1\x01\x02\x03\x04";
    let offset = profile
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap();
    let counts = &profile[offset - 32..offset];
    let expected: Vec<_> = [29_u32, 6, 26, 18, 52, 16, 544, 1120]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    assert_eq!(counts, expected);
    let mut suffix = &profile[offset + marker.len()..];
    for expected in [
        iroha_kagemusha_proof::a_relation::schedule::compiled::compiled_schedule_transcript()
            .unwrap(),
        producer_inventory::compiled_sigma_policy().unwrap(),
        iroha_kagemusha_proof::omega::native::compiled_policy_transcript().unwrap(),
    ] {
        let length = usize::try_from(u32::from_le_bytes(suffix[..4].try_into().unwrap())).unwrap();
        assert_eq!(&suffix[4..4 + length], expected);
        suffix = &suffix[4 + length..];
    }
    assert!(suffix.is_empty());
}

#[test]
fn inventory_item_transcript_binds_raw_bytes_shape_and_full_digests() {
    let mut item = ParsedArtifact {
        curve: CurveV1::Vesta,
        k: 12,
        descriptor_bytes: 11,
        descriptor_sha256: [2; 32],
        verifying_key_bytes: 13,
        verifying_key_sha256: [3; 32],
        descriptor_digest: [4; 32],
        verifying_key_digest: [5; 32],
        proof_bytes: 17,
    };
    let mut original = Vec::new();
    item.append(&mut original).unwrap();
    assert_eq!(original.len(), 142);
    assert_eq!(&original[..6], &[1, 12, 11, 0, 0, 0]);
    let digest = artifact_digest(b"artifact-inventory", &original);
    item.verifying_key_sha256[0] ^= 1;
    let mut changed = Vec::new();
    item.append(&mut changed).unwrap();
    assert_ne!(digest, artifact_digest(b"artifact-inventory", &changed));
    assert_ne!(digest, artifact_digest(b"native-profile", &original));
    assert_ne!(
        digest,
        artifact_digest(b"artifact-inventory", &original[..original.len() - 1])
    );
    let mut independently_framed = Vec::new();
    independently_framed.extend_from_slice(KAGEMUSHA_WALLET_DIGEST_PREFIX_V1);
    independently_framed.extend_from_slice(b"artifact-inventory\0");
    independently_framed.extend_from_slice(&(original.len() as u64).to_le_bytes());
    independently_framed.extend_from_slice(&original);
    assert_eq!(
        digest,
        <[u8; 32]>::from(Sha256::digest(&independently_framed))
    );
}

#[test]
fn frozen_protocol_digest_matches_independently_framed_native_originals() {
    // Golden preimages independently constructed from native source moduli, the checked-in
    // RP57 table originals and PINNED_PARAMS_V1. No test-produced key or verdict is used.
    let body = eq_protocol_transcript_v1().unwrap();
    assert_eq!(body.len(), 423);
    assert_eq!(
        hex::encode(Sha256::digest(&body)),
        "16793a98e248683d849e1c29b1022b408edb14af2f6f15bc95c7a61f2f79f4ea"
    );
    assert_eq!(
        hex::encode(artifact_digest(b"eq-protocol", &body)),
        "f8740dd567145d4146d8a970339bc72205ba4093aacb2c451702ce741b58c273"
    );
    let body = ep_protocol_transcript_v1().unwrap();
    assert_eq!(body.len(), 423);
    assert_eq!(
        hex::encode(Sha256::digest(&body)),
        "16fefdc12b8fa67594969413bec611825ca1db942b4782b4d6bc0eca06428d6d"
    );
    assert_eq!(
        hex::encode(artifact_digest(b"ep-protocol", &body)),
        "d828551f4e97743077174b94408253115fb622fdb0132ede8ed7d722de09fc3c"
    );
}

#[test]
fn native_profile_matches_complete_compiled_encoder_preimage() {
    // Exact native descriptor-policy prefix, followed by three complete compiled
    // source inventories. This does not freeze or qualify any actual producer keys.
    let mut original = hex::decode(concat!(
        "01000b000000010000000002000000000300000000030100000003020000000303000000040000000005000000000600",
        "000000070000000008000000005f0000004e52543000001c14315baa201047a077821817683104003700000000000000",
        "587ed1b1434089fd020201000401000000010c01100402000000040100000004010000000d0100000000000000040100",
        "00000d01000000000000000401000000730000004e52543000001c14315baa201047a077821817683104004b00000000",
        "0000000dea5f0df63cb40b02020100040000000001100110040200000004010000000401000000170300000000000000",
        "0401000000040200000004100000001703000000000000000401000000040000000004010000001d000000060000001a",
        "00000012000000340000001000000020020000600400006b67776f6d675f3101020304",
    )).unwrap();
    for policy in [
        iroha_kagemusha_proof::a_relation::schedule::compiled::compiled_schedule_transcript()
            .unwrap(),
        producer_inventory::compiled_sigma_policy().unwrap(),
        iroha_kagemusha_proof::omega::native::compiled_policy_transcript().unwrap(),
    ] {
        original.extend_from_slice(&u32::try_from(policy.len()).unwrap().to_le_bytes());
        original.extend_from_slice(&policy);
    }
    let body = native_profile_transcript_v1().unwrap();
    assert_eq!(body, original);
    eprintln!(
        "NATIVE_PROFILE bytes={} sha256={} digest={}",
        body.len(),
        hex::encode(Sha256::digest(&body)),
        hex::encode(artifact_digest(b"native-profile", &body))
    );
    assert_eq!(body.len(), 2_497);
    // Pin the complete compiled schedules, sigma policy and Omega layout of this source.
    assert_eq!(
        hex::encode(Sha256::digest(&body)),
        "ebe2ac209e566c09928f0e55513e51e1cde4302cb9ab79cad4b7d911c6c9e6bb"
    );
    assert_eq!(
        hex::encode(artifact_digest(b"native-profile", &body)),
        "cf97197687e1c985b7d29a716a52f1ac9a1e2adfc9a093b9dc17f836a3f8e74a"
    );
}
