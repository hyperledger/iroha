//! Captured public protocol frames and checked reconstruction contracts.

use std::fmt::Debug;

use iroha_crypto::{Algorithm, KeyPair};
use norito::{
    NoritoDeserialize, NoritoSerialize,
    codec::Encode as _,
    core as ncore,
    json::{JsonDeserialize, JsonSerialize, Value},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

use iroha_data_model::{
    account::AccountId,
    asset::AssetDefinitionId,
    confidential::{
        CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1, CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1,
        CONFIDENTIAL_MEMO_WIRE_MAGIC_V1, CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1,
        CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1, CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1,
        ConfidentialMemoEnvelopeV1, ConfidentialMemoRecipientSlotV1, ConfidentialMemoSuiteV1,
    },
    isi::repo::{RepoInstructionBox, RepoIsi, RepoMarginCallIsi, ReverseRepoIsi},
    kagemusha::kagemusha_wallet_v1::{KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1},
    privacy::{
        GoldilocksDigest384V1, PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1,
        PrivacyExact12CatalogCommitmentV1, PrivacyProofWireMagicV1,
    },
    repo::{RepoCashLeg, RepoCollateralLeg, RepoGovernance},
};
use iroha_model_base::domain::DomainId;

use crate::frame_identity_test_support::record_binary as record;

fn family<T>(rows: &mut Vec<Value>, name: &str, values: &[T])
where
    T: norito::NoritoSchema
        + Clone
        + Debug
        + PartialEq
        + NoritoSerialize
        + for<'de> NoritoDeserialize<'de>,
{
    assert!(!values.is_empty());
    for (index, value) in values.iter().enumerate() {
        assert!(
            !values[..index].contains(value),
            "distinct populated variants"
        );
        record(rows, &format!("{name}/root_{index}"), value);
        record(
            rows,
            &format!("{name}/option_{index}"),
            &Some(value.clone()),
        );
    }
    record(rows, &format!("{name}/option_none"), &None::<T>);
    record(rows, &format!("{name}/vec_empty"), &Vec::<T>::new());
    record(rows, &format!("{name}/vec_all"), &values.to_vec());
}

fn assert_json<T>(value: &T)
where
    T: Debug + PartialEq + NoritoSerialize + JsonSerialize + JsonDeserialize,
{
    let json = norito::json::to_json(value).unwrap();
    let decoded: T = norito::json::from_json(&json).unwrap();
    assert_eq!(&decoded, value);
    assert_eq!(decoded.encode(), value.encode());
    assert_eq!(norito::json::to_json(&decoded).unwrap(), json);
}

fn reject_payload<T>(bytes: &[u8])
where
    T: Debug + NoritoSerialize + for<'de> NoritoDeserialize<'de>,
{
    let flags = ncore::default_encode_flags();
    let frame = ncore::frame_bare_with_header_flags::<T>(bytes, flags)
        .expect("frame invalid fields with their correct header, length and checksum");
    let view = ncore::from_bytes_view(&frame).expect("authenticate the malformed-field frame");
    assert_eq!(view.as_bytes(), bytes);
    view.decode_exact_with::<T, _, _>(ncore::decode_field_canonical::<T>)
        .expect_err("checked reconstruction must reject malformed fields");
    assert!(norito::decode_canonical::<T>(&frame).is_err());
    let _flags = ncore::DecodeFlagsGuard::enter(flags);
    let _payload = ncore::PayloadCtxGuard::enter_with_schema_and_flags(bytes, view.schema(), flags);
    let archived = ncore::from_bytes::<T>(&frame).expect("authenticate typed archive metadata");
    <T as ncore::DeserializePayload<'_>>::try_deserialize(archived)
        .expect_err("the owner's fallible decoder must reject without panicking");
}

fn privacy_values(rows: &mut Vec<Value>) {
    let magic = PrivacyProofWireMagicV1::canonical();
    assert_eq!(magic.as_bytes(), &PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1);
    assert_eq!(magic.encode().as_slice(), magic.as_bytes().as_slice());
    for index in 0..8 {
        let mut malformed = *magic.as_bytes();
        malformed[index] ^= 1;
        reject_payload::<PrivacyProofWireMagicV1>(&malformed);
    }
    assert_json(&magic);
    family(rows, "privacy_proof_wire_magic", &[magic]);

    let modulus = fastpq_isi::poseidon::FIELD_MODULUS;
    let words = [0, 1, 2, 3, 4, modulus - 1];
    let first = GoldilocksDigest384V1::new(words).unwrap();
    let second = GoldilocksDigest384V1::new([9, 8, 7, 6, 5, 4]).unwrap();
    assert_eq!(first.words(), words);
    assert_eq!(first.encode(), first.to_le_bytes());
    for lane in 0..6 {
        for invalid in [modulus, u64::MAX] {
            let mut malformed = words;
            malformed[lane] = invalid;
            assert!(GoldilocksDigest384V1::new(malformed).is_none());
            let bytes: Vec<_> = malformed.into_iter().flat_map(u64::to_le_bytes).collect();
            reject_payload::<GoldilocksDigest384V1>(&bytes);
        }
    }
    assert_json(&first);
    assert_json(&second);
    family(rows, "goldilocks_digest384", &[first, second]);

    let catalog = PrivacyExact12CatalogCommitmentV1::canonical();
    assert_eq!(catalog.encode(), catalog.digest().encode());
    for lane in 0..6 {
        let mut words = catalog.digest().words();
        words[lane] = u64::from(words[lane] == 0);
        let different = GoldilocksDigest384V1::new(words).unwrap();
        assert_ne!(&different, catalog.digest());
        reject_payload::<PrivacyExact12CatalogCommitmentV1>(&different.encode());
    }
    assert_json(&catalog);
    family(rows, "privacy_exact12_catalog_commitment", &[catalog]);
}

fn memo_slots() -> [ConfidentialMemoRecipientSlotV1; CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1] {
    // Deterministic wire-shape fixtures, matching the existing envelope tests.
    // These byte patterns are not evidence of ML-KEM/AEAD authentication.
    core::array::from_fn(|index| {
        let suite = if index % 2 == 0 {
            ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305
        } else {
            ConfidentialMemoSuiteV1::MlKem1024XChaCha20Poly1305
        };
        let index = u8::try_from(index).unwrap();
        ConfidentialMemoRecipientSlotV1::new(
            suite,
            vec![index + 1; suite.encapsulation_bytes()],
            [index + 17; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
            [index + 33; CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1],
        )
        .unwrap()
    })
}

fn memo_values(rows: &mut Vec<Value>) {
    let slots = memo_slots();
    let nonce = [0xA5; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1];
    let ciphertext = vec![0x5A; CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1 + 32];
    let first = ConfidentialMemoEnvelopeV1::new(slots.clone(), nonce, ciphertext.clone()).unwrap();
    let second = ConfidentialMemoEnvelopeV1::new(
        slots.clone(),
        [0xB6; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
        vec![0x6B; CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1],
    )
    .unwrap();
    first.validate().unwrap();
    second.validate().unwrap();
    let wire = first.encode_wire().unwrap();
    assert_eq!(first.encode(), wire);
    assert_eq!(
        ConfidentialMemoEnvelopeV1::decode_wire(&wire).unwrap(),
        first
    );
    assert_eq!(first.slots().len(), 8);
    let mut duplicate = slots.clone();
    duplicate[2] = duplicate[0].clone();
    assert!(ConfidentialMemoEnvelopeV1::new(duplicate, nonce, ciphertext.clone()).is_err());
    assert!(ConfidentialMemoEnvelopeV1::new(slots.clone(), [0; 24], ciphertext.clone()).is_err());
    for length in [
        CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1 - 1,
        CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1 + 1,
    ] {
        assert!(ConfidentialMemoEnvelopeV1::new(slots.clone(), nonce, vec![1; length]).is_err());
    }
    let mut invalid_magic = wire.clone();
    invalid_magic[0] ^= 1;
    reject_payload::<ConfidentialMemoEnvelopeV1>(&invalid_magic);
    let slot_start = CONFIDENTIAL_MEMO_WIRE_MAGIC_V1.len();
    let mut invalid_suite = wire.clone();
    invalid_suite[slot_start] = 2;
    reject_payload::<ConfidentialMemoEnvelopeV1>(&invalid_suite);
    let encapsulation_start = slot_start + 1;
    let wrap_nonce_start = encapsulation_start + slots[0].suite().encapsulation_bytes();
    let wrapped_key_start = wrap_nonce_start + CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1;
    let first_slot_end = wrapped_key_start + CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1;
    for (start, end) in [
        (encapsulation_start, wrap_nonce_start),
        (wrap_nonce_start, wrapped_key_start),
        (wrapped_key_start, first_slot_end),
    ] {
        let mut placeholder = wire.clone();
        placeholder[start..end].fill(0);
        reject_payload::<ConfidentialMemoEnvelopeV1>(&placeholder);
    }
    let body_nonce_start = slot_start
        + slots
            .iter()
            .map(|slot| {
                1 + slot.suite().encapsulation_bytes()
                    + CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1
                    + CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1
            })
            .sum::<usize>();
    let body_length_start = body_nonce_start + CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1;
    assert_eq!(
        wire[body_length_start],
        u8::try_from(ciphertext.len()).unwrap()
    );
    let mut zero_nonce = wire.clone();
    zero_nonce[body_nonce_start..body_length_start].fill(0);
    reject_payload::<ConfidentialMemoEnvelopeV1>(&zero_nonce);
    let mut noncanonical_length = wire[..body_length_start].to_vec();
    noncanonical_length.extend_from_slice(&[0xB0, 0]);
    noncanonical_length.extend_from_slice(&ciphertext);
    reject_payload::<ConfidentialMemoEnvelopeV1>(&noncanonical_length);
    reject_payload::<ConfidentialMemoEnvelopeV1>(&wire[..wire.len() - 1]);
    assert_json(&first);
    assert_json(&second);
    family(rows, "confidential_memo_envelope", &[first, second]);
}

fn kagemusha_values(rows: &mut Vec<Value>) {
    let mut keys = Vec::new();
    let mut signatures = Vec::new();
    for seed in [0x39, 0x57] {
        // Public deterministic test seeds, never runtime device authority keys.
        let signer = SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
        let public = signer.verifying_key().to_encoded_point(false);
        let key = KagemushaDevicePublicKeyV1::from_sec1_bytes(public.as_bytes()).unwrap();
        let message = b"public manual identity capture";
        let signature: Signature = signer.sign(message);
        let low = signature.normalize_s().unwrap_or(signature);
        let signature = KagemushaDeviceSignatureV1::from_raw_bytes(&low.to_bytes()).unwrap();
        key.validate().unwrap();
        signature.validate().unwrap();
        signature.verify(&key, message).unwrap();
        assert!(signature.verify(&key, b"different message").is_err());
        assert_eq!(key.encode().as_slice(), key.as_sec1_bytes().as_slice());
        assert_eq!(
            signature.encode().as_slice(),
            signature.as_raw_bytes().as_slice()
        );
        let decoded: KagemushaDeviceSignatureV1 =
            norito::decode_canonical(&norito::encode_canonical(&signature).unwrap()).unwrap();
        decoded.verify(&key, message).unwrap();
        assert!(
            KagemushaDevicePublicKeyV1::from_sec1_bytes(
                signer.verifying_key().to_encoded_point(true).as_bytes()
            )
            .is_err()
        );
        assert_json(&key);
        assert_json(&signature);
        keys.push(key);
        signatures.push(signature);
    }
    assert!(KagemushaDevicePublicKeyV1::from_sec1_bytes(&keys[0].as_sec1_bytes()[..64]).is_err());
    let mut invalid_point = [0; 65];
    invalid_point[0] = 4;
    assert!(KagemushaDevicePublicKeyV1::from_sec1_bytes(&invalid_point).is_err());
    reject_payload::<KagemushaDevicePublicKeyV1>(&invalid_point);
    let mut wrong_prefix = *keys[0].as_sec1_bytes();
    wrong_prefix[0] = 2;
    reject_payload::<KagemushaDevicePublicKeyV1>(&wrong_prefix);
    assert!(
        KagemushaDeviceSignatureV1::from_raw_bytes(&signatures[0].as_raw_bytes()[..63]).is_err()
    );
    for range in [0..32, 32..64] {
        let mut zero_scalar = *signatures[0].as_raw_bytes();
        zero_scalar[range].fill(0);
        assert!(KagemushaDeviceSignatureV1::from_raw_bytes(&zero_scalar).is_err());
        reject_payload::<KagemushaDeviceSignatureV1>(&zero_scalar);
    }
    let high = Signature::from_scalars(
        p256::Scalar::ONE.to_bytes(),
        (-p256::Scalar::ONE).to_bytes(),
    )
    .unwrap();
    assert!(high.normalize_s().is_some());
    assert!(KagemushaDeviceSignatureV1::from_raw_bytes(&high.to_bytes()).is_err());
    reject_payload::<KagemushaDeviceSignatureV1>(&high.to_bytes());
    family(rows, "kagemusha_device_public_key", &keys);
    family(rows, "kagemusha_device_signature", &signatures);
}

fn repo_values(rows: &mut Vec<Value>) {
    let account = |seed| {
        let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap();
        AccountId::new(key.public_key().clone())
    };
    let domain = DomainId::try_new("wonderland", "universal").unwrap();
    let asset = |name: &str| {
        AssetDefinitionId::derive_from_components(domain.clone(), name.parse().unwrap())
    };
    let agreement = "daily_repo".parse().unwrap();
    let initiate = RepoIsi::new(
        agreement,
        account(0x11),
        account(0x22),
        Some(account(0x33)),
        RepoCashLeg::new(asset("usd"), 1_000u32),
        RepoCollateralLeg::new(asset("bond"), 1_100u32),
        250,
        1_704_000_000_000,
        RepoGovernance::with_defaults(1_500, 86_400),
    );
    let initiation_consent = initiate.initiation_intent_hash();
    let maturity_consent = initiate.maturity_intent_hash();
    assert_ne!(initiation_consent, maturity_consent);
    let values = [
        RepoInstructionBox::from(initiate),
        RepoInstructionBox::Reverse(ReverseRepoIsi::new("daily_repo".parse().unwrap())),
        RepoInstructionBox::MarginCall(RepoMarginCallIsi::new("daily_repo".parse().unwrap())),
    ];
    for (tag, value) in (0u32..3).zip(&values) {
        assert_eq!(&value.encode()[..4], &tag.to_le_bytes());
        let mut unknown = value.encode();
        unknown[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        reject_payload::<RepoInstructionBox>(&unknown);
    }
    let decoded: RepoInstructionBox =
        norito::decode_canonical(&norito::encode_canonical(&values[0]).unwrap()).unwrap();
    let RepoInstructionBox::Initiate(decoded) = decoded else {
        panic!("initiate tag must stay initiate")
    };
    assert_eq!(decoded.initiation_intent_hash(), initiation_consent);
    assert_eq!(decoded.maturity_intent_hash(), maturity_consent);
    for length in 0..4 {
        reject_payload::<RepoInstructionBox>(&values[1].encode()[..length]);
    }
    // This owner has a binary instruction-registry contract, not a standalone JSON API.
    family(rows, "repo_instruction_box", &values);
}

#[test]
fn manual_protocol_frames_match_capture() {
    let mut rows = Vec::new();
    privacy_values(&mut rows);
    memo_values(&mut rows);
    kagemusha_values(&mut rows);
    repo_values(&mut rows);
    assert_eq!(rows.len(), 47);
    let evidence = norito::json!({
        "format_version": 1,
        "purpose": "seven public manual protocol owners before identity declaration",
        "default_encode_flags": (ncore::default_encode_flags()),
        "rows": rows,
    });
    let expected: Value = norito::json::from_json(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/manual_protocol_identity_frames.json"
    )))
    .expect("immutable pre-declaration protocol capture");
    assert_eq!(evidence, expected);
}
