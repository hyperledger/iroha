use ff::Field;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

use super::*;

fn public() -> KagemushaWalletLineagePublicV1 {
    let signer = SigningKey::from_slice(&[7; 32]).expect("test signing key");
    let encoded = signer.verifying_key().to_encoded_point(false);
    KagemushaWalletLineagePublicV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: core::array::from_fn(|index| u8::try_from(index).unwrap() + 1),
        relation_id: core::array::from_fn(|index| u8::try_from(index).unwrap() + 33),
        head: KagemushaWalletStateCommitmentV1 {
            value: Fp::from(9).to_repr(),
        },
        wallet_id: core::array::from_fn(|index| u8::try_from(index).unwrap() + 65),
        credential_digest: Fp::from(11).to_repr(),
        payment_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(encoded.as_bytes())
            .expect("canonical test public key"),
        lifecycle: KagemushaWalletLifecycleV1::Retiring,
        policy_epoch: 0x0102_0304_0506_0708,
        enabled_controls: KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
        burned_total: u128::MAX,
        pending_outgoing_root: Fp::from(13).to_repr(),
        credit_digest_root: Fp::from(17).to_repr(),
    }
}

fn limb(bytes: &[u8]) -> Fp {
    let mut repr = [0; 32];
    repr[..bytes.len()].copy_from_slice(bytes);
    Option::<Fp>::from(Fp::from_repr(repr)).expect("bounded limb")
}

#[test]
fn field_conversion_rejects_noncanonical_aliases_and_wrong_dimensions() {
    assert_eq!(
        fields::<2>(vec![Fp::ONE.to_repr(), Fp::from(2).to_repr()]).unwrap(),
        [Fp::ONE, Fp::from(2)]
    );
    assert_eq!(fields::<1>(vec![]), Err(Error::Authority));
    assert_eq!(
        fields::<1>(vec![Fp::ZERO.to_repr(), Fp::ONE.to_repr()]),
        Err(Error::Authority)
    );
    assert_eq!(fields::<1>(vec![[0xff; 32]]), Err(Error::Authority));
    // An encoding of -1 is retained exactly; a noncanonical integer is never reduced.
    assert_eq!(fields::<1>(vec![(-Fp::ONE).to_repr()]).unwrap(), [-Fp::ONE]);
}

#[test]
fn omega_public_prefix_matches_g1_identity_order_and_key_endianness() {
    let public = public();
    let key_digest = Fp::from(19).to_repr();
    let prefix = lineage_public_fields(&public, key_digest).unwrap();
    assert_eq!(prefix[0], Fp::from(u64::from(public.version)));
    assert_eq!(prefix[1], limb(&public.scheme_id[..16]));
    assert_eq!(prefix[2], limb(&public.scheme_id[16..]));
    assert_eq!(prefix[3], limb(&public.relation_id[..16]));
    assert_eq!(prefix[4], limb(&public.relation_id[16..]));
    assert_eq!(prefix[5].to_repr(), public.head.value);
    assert_eq!(prefix[6], limb(&public.wallet_id[..16]));
    assert_eq!(prefix[7], limb(&public.wallet_id[16..]));
    assert_eq!(prefix[8].to_repr(), public.credential_digest);
    let key = public.payment_key.as_sec1_bytes();
    for (coordinate, offset) in [(&key[1..33], 9), (&key[33..65], 11)] {
        let little_endian: Vec<_> = coordinate.iter().copied().rev().collect();
        assert_eq!(prefix[offset], limb(&little_endian[..16]));
        assert_eq!(prefix[offset + 1], limb(&little_endian[16..]));
    }
    let packed = u128::from(public.lifecycle.tag())
        | (u128::from(public.policy_epoch) << 8)
        | (u128::from(public.enabled_controls) << 72);
    assert_eq!(
        prefix[13].to_repr(),
        kagemusha_wallet_field_from_u128_v1(packed)
    );
    assert_eq!(
        prefix[14].to_repr(),
        kagemusha_wallet_field_from_u128_v1(public.burned_total)
    );
    assert_eq!(prefix[15].to_repr(), public.pending_outgoing_root);
    assert_eq!(prefix[16].to_repr(), public.credit_digest_root);
    assert_eq!(prefix[17].to_repr(), key_digest);
}

#[test]
fn omega_public_prefix_never_ignores_installed_key_or_invalid_wire_field() {
    let public = public();
    let first = lineage_public_fields(&public, Fp::from(19).to_repr()).unwrap();
    let second = lineage_public_fields(&public, Fp::from(23).to_repr()).unwrap();
    assert_eq!(&first[..17], &second[..17]);
    assert_ne!(first[17], second[17]);
    assert_eq!(
        lineage_public_fields(&public, [0xff; 32]),
        Err(Error::Authority)
    );
    let mut malformed = public;
    malformed.pending_outgoing_root = [0xff; 32];
    assert_eq!(
        lineage_public_fields(&malformed, Fp::ONE.to_repr()),
        Err(Error::Authority)
    );
}

#[test]
fn retained_original_rejects_ambiguous_role_even_for_identical_bytes() {
    use KagemushaWalletRetainedInputRoleV1 as Role;
    let original = KagemushaWalletRetainedInputV1 {
        role: Role::LoadReceipt,
        bytes: vec![1, 2, 3],
    };
    let unrelated = KagemushaWalletRetainedInputV1 {
        role: Role::CertificateSet,
        bytes: vec![4, 5],
    };
    assert_eq!(
        retained_original(&[original.clone(), unrelated], Role::LoadReceipt).unwrap(),
        [1, 2, 3]
    );
    assert_eq!(
        retained_original(&[], Role::LoadReceipt),
        Err(Error::Authority)
    );
    assert_eq!(
        retained_original(&[original.clone(), original], Role::LoadReceipt),
        Err(Error::Authority)
    );
    assert_eq!(
        retained_original(
            &[KagemushaWalletRetainedInputV1 {
                role: Role::LoadReceipt,
                bytes: vec![]
            }],
            Role::LoadReceipt
        ),
        Err(Error::Authority)
    );
}

#[test]
fn signed_tape_preserves_actual_body_and_canonical_signature_bytes() {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let signature: Signature = key.sign(b"original tape component test");
    let signature = signature.normalize_s().unwrap_or(signature);
    let canonical =
        KagemushaDeviceSignatureV1::from_raw_bytes(signature.to_bytes().as_slice()).unwrap();
    let body = vec![0, 1, 255, 3];
    let tape = signed_tape(body.clone(), &canonical);
    assert_eq!(&tape[..body.len()], &body);
    assert_eq!(&tape[body.len()..], canonical.as_raw_bytes());
    assert_eq!(tape.len(), body.len() + 64);
}

// These tests exercise conversion only. The deliberately unverified certificate
// bytes cannot authorize the pre-Advance native BLS check.
fn load_originals() -> (Vec<KagemushaWalletRetainedInputV1>, [u8; 32]) {
    let fixture: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../fixtures/kagemusha/ordinary_load_receipt_v1.json"
    ))
    .unwrap();
    let bytes = hex::decode(fixture["receipt_frame_hex"].as_str().unwrap()).unwrap();
    let receipt = KagemushaWalletLoadReceiptV1::decode_canonical(&bytes).unwrap();
    let digest = receipt.receipt_digest().unwrap();
    let event = iroha_data_model::events::EventBox::Data(
        iroha_data_model::events::data::DataEvent::KagemushaLoadCommitted(
            iroha_data_model::events::data::kagemusha::KagemushaLoadCommittedV1::from_receipt(
                &receipt,
            )
            .unwrap(),
        )
        .into(),
    );
    let tree: iroha_crypto::MerkleTree<iroha_data_model::events::EventBox> =
        [iroha_crypto::HashOf::new(&event)].into_iter().collect();
    let finality = KagemushaWalletLoadFinalityV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        receipt_digest: digest,
        certificate: iroha_data_model::sumeragi_finality::SumeragiCommitCertificateV1 {
            consensus_header: vec![1],
            commit_qc: vec![2],
            result_preimage: vec![3],
        },
        event_proof: tree.get_proof(0).unwrap(),
    };
    (
        vec![
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::LoadReceipt,
                bytes,
            },
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::LoadFinality,
                bytes: finality.to_canonical_bytes().unwrap(),
            },
        ],
        digest,
    )
}

#[test]
fn retained_load_conversion_preserves_original_refusal_and_retry() {
    let (inputs, digest) = load_originals();
    let expected = retained_load_source(&inputs, digest).unwrap();
    let unchanged = inputs.clone();
    for limits in [
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
    ] {
        let error =
            norito::with_decode_limits_scope(limits, || retained_load_source(&inputs, digest))
                .unwrap_err();
        assert!(
            matches!(error, wallet_state::Error::DecodeResource(ref original)
            if original.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit)
        );
        assert_eq!(inputs, unchanged);
        assert_eq!(retained_load_source(&inputs, digest).unwrap(), expected);
    }
    let mut malformed = inputs.clone();
    malformed[1].bytes = vec![0];
    assert!(matches!(
        retained_load_source(&malformed, digest),
        Err(wallet_state::Error::Proof(_))
    ));
}

#[test]
fn load_original_conversion_preserves_native_certificates_without_granting_finality() {
    let (inputs, digest) = load_originals();
    let (receipt, source) = retained_load_source(&inputs, digest).unwrap();
    let original = KagemushaWalletLoadFinalityV1::decode_canonical(&inputs[1].bytes).unwrap();
    assert_eq!(receipt.receipt_digest().unwrap(), digest);
    assert_eq!(source, original);
    let native = iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture::new_with_explicit_parameters();
    assert!(source.verify(&native.verifier(), &receipt).is_err());
}

#[test]
fn load_original_conversion_rejects_lost_ambiguous_corrupt_or_cross_receipt_custody() {
    let (inputs, digest) = load_originals();
    assert!(retained_load_source(&inputs, Fp::ONE.to_repr()).is_err());
    for role in 0..2 {
        let mut missing = inputs.clone();
        missing.remove(role);
        assert!(retained_load_source(&missing, digest).is_err());
        let mut duplicate = inputs.clone();
        duplicate.push(inputs[role].clone());
        assert!(retained_load_source(&duplicate, digest).is_err());
        let mut changed = inputs.clone();
        changed[role].bytes.push(0);
        assert!(retained_load_source(&changed, digest).is_err());
    }
    let mut cross_receipt = inputs.clone();
    let mut receipt = KagemushaWalletLoadReceiptV1::decode_canonical(&inputs[0].bytes).unwrap();
    receipt.request_id[0] ^= 1;
    cross_receipt[0].bytes = receipt.to_canonical_bytes().unwrap();
    assert!(retained_load_source(&cross_receipt, digest).is_err());

    let mut cross_finality = inputs.clone();
    let mut finality = KagemushaWalletLoadFinalityV1::decode_canonical(&inputs[1].bytes).unwrap();
    finality.receipt_digest = Fp::ONE.to_repr();
    cross_finality[1].bytes = finality.to_canonical_bytes().unwrap();
    assert!(retained_load_source(&cross_finality, digest).is_err());
}

#[test]
fn authority_original_readers_preserve_real_refusal_and_exact_retry() {
    let all: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let bytes = |name: &str| {
        let row = all["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"].as_str() == Some(name))
            .unwrap();
        hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()
    };
    let scheme: KagemushaWalletSchemeV1 =
        norito::decode_canonical(&bytes("KagemushaWalletSchemeV1")).unwrap();
    let manifest_bytes = bytes("KagemushaWalletArtifactManifestV1");
    let manifest =
        KagemushaWalletArtifactManifestV1::decode_canonical(&manifest_bytes, &scheme).unwrap();
    let allowlist = bytes("KagemushaWalletVerifyingKeyAllowlistV1");
    let credential = bytes("KagemushaWalletCredentialV1");
    let certificate = bytes("KagemushaWalletSignerCertificateV1");
    let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
    macro_rules! check {
        ($read:expr) => {{
            let expected = read_model($read).unwrap();
            let error = norito::with_decode_limits_scope(limits, || read_model($read)).unwrap_err();
            assert!(matches!(error, Error::DecodeResource(ref original)
                if original.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
            assert_eq!(read_model($read).unwrap(), expected);
        }};
    }
    check!(|| KagemushaWalletArtifactManifestV1::decode_canonical(&manifest_bytes, &scheme));
    check!(|| KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(&allowlist, &manifest.body));
    check!(|| KagemushaWalletCredentialV1::decode_canonical(&credential, &scheme.scheme_id()));
    check!(|| KagemushaWalletSignerCertificateV1::decode_canonical(&certificate, &scheme));
    assert!(matches!(
        read_model(|| KagemushaWalletCredentialV1::decode_canonical(&[0], &scheme.scheme_id())),
        Err(Error::Authority)
    ));
    let original = norito::encode_canonical(&vec![7u8; 128]).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let error = norito::with_decode_limits_scope(limits, || {
        read_original(|| {
            norito::decode_canonical_with_limits::<Vec<u8>>(
                &original,
                norito::canonical_decode_limits(original.len()),
            )
        })
    })
    .unwrap_err();
    assert!(matches!(error, Error::DecodeResource(ref cause)
        if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
    assert_eq!(
        read_original(|| norito::decode_canonical_with_limits::<Vec<u8>>(
            &original,
            norito::canonical_decode_limits(original.len())
        ))
        .unwrap(),
        vec![7; 128]
    );
}
