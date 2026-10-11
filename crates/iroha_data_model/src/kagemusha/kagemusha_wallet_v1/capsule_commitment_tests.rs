//! Primitive KATs and validated private-wrapper custody/codec checks.
//!
//! Synthetic primitive bodies and stand-in proof fixtures establish encoding and
//! owner admission only, not proof validity or complete C12 privacy qualification.

use super::super::KagemushaWalletEvidenceKindV1;
use super::super::identity::identity_tests::identity_fixture;
use super::*;
use iroha_pasta::{Eq, Fp, PastaCurve};

fn word(hex: &str) -> [u8; 32] {
    hex::decode(hex)
        .expect("fixed hex")
        .try_into()
        .expect("32 bytes")
}

fn one() -> [u8; 32] {
    let mut value = [0; 32];
    value[0] = 1;
    value
}

fn fixture() -> KagemushaWalletRecoveryCapsuleV1 {
    super::custody_tests::bootstrap_capsule(&identity_fixture(
        KagemushaWalletEvidenceKindV1::AndroidKeyMintTee,
        0x65,
    ))
}

fn encoded<C: PastaCurve<ScalarExt = Fp>>(point: C) -> [u8; 32] {
    point.to_bytes()
}

#[test]
fn capsule_parameters_match_the_existing_eq_derivation() {
    for (base, message) in
        CAPSULE_BASES_V1
            .iter()
            .zip([&[0, 0, 0, 0, 0][..], &[0, 1, 0, 0, 0][..], &[1][..]])
    {
        assert_eq!(
            *base,
            encoded(Eq::hash_to_curve("Halo2-Parameters", message).unwrap())
        );
    }
}

#[test]
fn capsule_primitive_canonical_openings_and_both_digest_halves_are_bound() {
    let zero = [0; 32];
    let maximum = word("00000000ed302d991bf94c09fc98462200000000000000000000000000000040");
    assert_eq!(capsule_point_v1::<Eq>(&zero, &zero).unwrap(), zero);
    for opening in [zero, one(), maximum] {
        let original = capsule_point_v1::<Eq>(&[17; 32], &opening).unwrap();
        for byte in [0, 15, 16, 31] {
            let mut digest = [17; 32];
            digest[byte] ^= 1;
            assert_ne!(capsule_point_v1::<Eq>(&digest, &opening).unwrap(), original);
        }
    }
    let mut modulus = maximum;
    modulus[0] = 1;
    let mut above = modulus;
    above[0] = 2;
    for bad in [modulus, above, [255; 32]] {
        assert!(capsule_point_v1::<Eq>(&[17; 32], &bad).is_err());
        assert!(
            fixture()
                .body()
                .clone()
                .freeze()
                .unwrap()
                .seal(bad)
                .is_err()
        );
    }
}

#[test]
fn capsule_owner_and_wire_are_identical_and_retry_preserves_the_opening() {
    let original = fixture();
    let frozen = original.body().clone().freeze().unwrap();
    assert_eq!(frozen.body(), original.body());
    let body_frame = frozen.body().to_canonical_bytes().unwrap();
    let sealed = frozen.seal(one()).unwrap();
    let wire = KagemushaWalletRecoveryCapsuleFrameV1 {
        body_frame,
        opening: one(),
    };
    let expected = norito::encode_canonical(&wire).unwrap();
    assert_eq!(sealed.as_canonical_bytes(), expected);
    assert_eq!(norito::encode_canonical(&sealed).unwrap(), expected);
    assert_eq!(
        sealed.custody_digest(),
        kagemusha_wallet_digest_v1(Role::Capsule, &expected)
    );
    assert_ne!(sealed.custody_digest(), sealed.receipt_commitment());
    for decoded in [
        KagemushaWalletRecoveryCapsuleV1::decode_canonical(&expected, &sealed.body().scheme_id)
            .unwrap(),
        norito::decode_canonical::<KagemushaWalletRecoveryCapsuleV1>(&expected).unwrap(),
    ] {
        assert_eq!(decoded, sealed);
        assert_eq!(decoded.to_canonical_bytes(), expected);
        assert_eq!(decoded.wire.opening, one());
        assert_eq!(
            decoded.proof_digest().unwrap(),
            sealed.body().proof_digest().unwrap()
        );
        assert_eq!(decoded.head_marker_state(), sealed.head_marker_state());
    }
    assert_ne!(original.custody_digest(), sealed.custody_digest());
    assert_ne!(original.receipt_commitment(), sealed.receipt_commitment());
    let mut changed = original.body().clone();
    changed
        .retained_inputs
        .push(KagemushaWalletRetainedInputV1 {
            role: KagemushaWalletRetainedInputRoleV1::CertificateSet,
            bytes: vec![1],
        });
    let changed = changed.freeze().unwrap().seal(one()).unwrap();
    assert_ne!(changed.custody_digest(), sealed.custody_digest());
    assert_ne!(changed.receipt_commitment(), sealed.receipt_commitment());
    assert_eq!(
        format!("{sealed:?}"),
        "KagemushaWalletRecoveryCapsuleV1 { .. }"
    );
    assert_eq!(
        format!("{wire:?}"),
        "KagemushaWalletRecoveryCapsuleFrameV1 { .. }"
    );
}

#[derive(Debug, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(name = "kagemusha.tests.CapsuleEnvelope")]
struct Envelope {
    capsule: KagemushaWalletRecoveryCapsuleV1,
    tail: u64,
}

#[test]
fn capsule_payload_prefix_rebuilds_owner_and_preserves_outer_trailer() {
    let capsule = fixture();
    let payload = capsule.wire.encode();
    let mut with_trailer = payload.clone();
    with_trailer.extend([19, 23, 29]);
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let (restored, used) =
        <KagemushaWalletRecoveryCapsuleV1 as norito::core::DecodeFromSlice>::decode_from_slice(
            &with_trailer,
        )
        .unwrap();
    assert_eq!(restored, capsule);
    assert_eq!(used, payload.len());
    assert_eq!(&with_trailer[used..], &[19, 23, 29]);
    assert!(
        <KagemushaWalletRecoveryCapsuleV1 as norito::core::DecodeFromSlice>::decode_from_slice(
            &payload[..payload.len() - 1],
        )
        .is_err()
    );
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "kagemusha.tests.CapsuleEnvelope")]
struct EnvelopeData {
    capsule: KagemushaWalletRecoveryCapsuleFrameV1,
    tail: u64,
}

#[test]
fn capsule_nested_canonical_codec_rebuilds_caches_and_rejects_malformed_data() {
    let capsule = fixture();
    let expected = Envelope {
        capsule: capsule.clone(),
        tail: 47,
    };
    let bytes = norito::encode_canonical(&expected).unwrap();
    assert_eq!(
        norito::decode_canonical::<Envelope>(&bytes).unwrap(),
        expected
    );
    for change in 0..5 {
        let mut wire = capsule.wire.clone();
        match change {
            0 => wire.opening = [255; 32],
            1 => wire.body_frame.push(0),
            2 => {
                wire.body_frame.pop();
            }
            3 => {
                let mut body = capsule.body().clone();
                body.operation_id[0] ^= 1;
                wire.body_frame = norito::encode_canonical(&body).unwrap();
            }
            _ => {
                let mut body = capsule.body().clone();
                body.successor_state.version = 2;
                wire.body_frame = norito::encode_canonical(&body).unwrap();
            }
        }
        let frame = norito::encode_canonical(&wire).unwrap();
        assert!(
            KagemushaWalletRecoveryCapsuleV1::decode_canonical(&frame, &capsule.body().scheme_id)
                .is_err()
        );
        assert!(norito::decode_canonical::<KagemushaWalletRecoveryCapsuleV1>(&frame).is_err());
        let nested = norito::encode_canonical(&EnvelopeData {
            capsule: wire,
            tail: 47,
        })
        .unwrap();
        assert!(norito::decode_canonical::<Envelope>(&nested).is_err());
    }
    for malformed in [
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.as_slice(), &[0]].concat(),
    ] {
        assert!(norito::decode_canonical::<Envelope>(&malformed).is_err());
    }
}

#[test]
fn capsule_freeze_enforces_the_exact_complete_wrapper_cap_before_opening() {
    let base = fixture();
    let body = |length| {
        let mut body = base.body().clone();
        body.retained_inputs.push(KagemushaWalletRetainedInputV1 {
            role: KagemushaWalletRetainedInputRoleV1::CertificateSet,
            bytes: vec![1; length],
        });
        body
    };
    let wrapper_len = |length| {
        let wire = KagemushaWalletRecoveryCapsuleFrameV1 {
            body_frame: norito::encode_canonical(&body(length)).unwrap(),
            opening: [0; 32],
        };
        norito::encode_canonical(&wire).unwrap().len()
    };
    let (mut low, mut high) = (1, KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1);
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if wrapper_len(mid) <= KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1 {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    assert_eq!(wrapper_len(low), KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1);
    for length in [low - 1, low] {
        let capsule = body(length).freeze().unwrap().seal([0; 32]).unwrap();
        assert_eq!(capsule.as_canonical_bytes().len(), wrapper_len(length));
        assert_eq!(
            norito::decode_canonical::<KagemushaWalletRecoveryCapsuleV1>(
                capsule.as_canonical_bytes()
            )
            .unwrap(),
            capsule
        );
    }
    assert_eq!(
        wrapper_len(low + 1),
        KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1 + 1
    );
    let too_large = body(low + 1);
    assert!(too_large.to_canonical_bytes().unwrap().len() < KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1);
    assert!(too_large.clone().freeze().is_err());
    let wire = KagemushaWalletRecoveryCapsuleFrameV1 {
        body_frame: too_large.to_canonical_bytes().unwrap(),
        opening: [0; 32],
    };
    let frame = norito::encode_canonical(&wire).unwrap();
    assert!(
        KagemushaWalletRecoveryCapsuleV1::decode_canonical(&frame, &base.body().scheme_id).is_err()
    );
    assert!(norito::decode_canonical::<KagemushaWalletRecoveryCapsuleV1>(&frame).is_err());
    let nested = norito::encode_canonical(&EnvelopeData {
        capsule: wire,
        tail: 47,
    })
    .unwrap();
    assert!(norito::decode_canonical::<Envelope>(&nested).is_err());
    assert!(
        body(KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1)
            .to_canonical_bytes()
            .is_err()
    );
}

#[test]
fn capsule_schema_and_padding_describe_only_body_frame_and_opening() {
    use iroha_schema::Metadata;
    assert_eq!(
        norito::core::archived_payload_align::<KagemushaWalletRecoveryCapsuleV1>(),
        norito::core::archived_payload_align::<KagemushaWalletRecoveryCapsuleFrameV1>()
    );
    let capsule = fixture();
    let frame = norito::encode_canonical(&capsule).unwrap();
    assert_eq!(frame, norito::encode_canonical(&capsule.wire).unwrap());
    let schema = KagemushaWalletRecoveryCapsuleV1::schema();
    let Metadata::Struct(fields) = schema.get::<KagemushaWalletRecoveryCapsuleV1>().unwrap() else {
        panic!("wire struct schema");
    };
    assert_eq!(
        fields
            .declarations
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>(),
        ["body_frame", "opening"]
    );
}

#[test]
fn capsule_primitive_matches_seven_independent_reference_vectors() {
    // Frozen Python reference, independently compared with the native primitive.
    // These byte patterns are deliberately not valid recovery bodies.
    for (length, ascending, opening, digest, point, identifier) in [
        (
            0,
            false,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "234720f36fac2a1d85ecb4943522c78919584370605c9371de1d1347e53d728c",
            "aba38dbd0145f38b3af289fb2c3d51ddf83265d8718523e41b85011a84e9729b",
            "626e653ff5874f249e73decbb1080c74d6aa74404b34094fc64645c53d138125",
        ),
        (
            0,
            false,
            "0100000000000000000000000000000000000000000000000000000000000000",
            "234720f36fac2a1d85ecb4943522c78919584370605c9371de1d1347e53d728c",
            "3a8646929d0e930cd810f046357d86d0b51580a27f183c4b1d179d23bcf40d99",
            "ff793ccb816729c834d89a4cff73381639e1ee58310404bda42ce4468d431f33",
        ),
        (
            0,
            false,
            "00000000ed302d991bf94c09fc98462200000000000000000000000000000040",
            "234720f36fac2a1d85ecb4943522c78919584370605c9371de1d1347e53d728c",
            "7acb139422da310d0a841c9b44a34a48f2e076b67262e21570860696ab317d26",
            "c52f2bdc1fafc4d2d4f8bae9d52713a1e98defdb4dd074075f433398241f9731",
        ),
        (
            31,
            true,
            "0100000000000000000000000000000000000000000000000000000000000000",
            "92aa0a4b84742c85bb87d85ff6fa762bba9b628aee3c36ba7866c54f6d9d57c4",
            "d862c9a65dc05ea94330dee7de245d9ae5ca6dae264d11b291b4790dd0b2da15",
            "ff687d0480c718043b62f408a3a657acf8c9dc827b7f195bfba04680fa59ff38",
        ),
        (
            32,
            true,
            "0100000000000000000000000000000000000000000000000000000000000000",
            "c284caae8b1ac33a11145dda1c2baca99c427497921216268d9078f098d661e1",
            "220315e02d4fb52f5d34367ff813abcee8fb976760284cda69561f868ea7ea3b",
            "a5f5082a9e3f741df64b17a6396660261f31bc01d4726277cddf267c50bd6b31",
        ),
        (
            255,
            true,
            "00000000ed302d991bf94c09fc98462200000000000000000000000000000040",
            "33418fc0422507d48b4570f1fc03c7d6a1bd6ba804ed0f417469d529fd507541",
            "7542e2eda056fb1418249c76e5e76ee108417b82d0d4836f1a749b80f8571838",
            "08a7f46714db21631748b4f9de69b00400812de3b738c9d72a026023af07dc0b",
        ),
        (
            524288,
            false,
            "0100000000000000000000000000000000000000000000000000000000000000",
            "8efa151993f8e0097aef8139b54a8cedf9d31f87c550a385df3d1f6bce2cb160",
            "936767447b947b34cef5d45c0dbb0b6d74d03817d10ea5e6fb3a98e91f84399c",
            "81c603d32549bdfcdb0bdf04c42073c3aab8f2783a75b59b680ec8f3825ce83e",
        ),
    ] {
        let body: Vec<u8> = (0..length)
            .map(|i| {
                if ascending {
                    u8::try_from(i).unwrap()
                } else {
                    0
                }
            })
            .collect();
        let digest_actual = kagemusha_wallet_digest_v1(Role::CapsuleBody, &body);
        assert_eq!(digest_actual, word(digest));
        let point_actual = capsule_point_v1::<Eq>(&digest_actual, &word(opening)).unwrap();
        assert_eq!(point_actual, word(point));
        assert_eq!(
            super::super::poseidon::kagemusha_wallet_poseidon_bytes_v1(
                super::super::poseidon::KAGEMUSHA_WALLET_CAPSULE_COMMITMENT_DOMAIN_V1,
                &point_actual,
            ),
            word(identifier)
        );
    }
}
