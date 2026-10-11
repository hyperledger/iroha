//! Bounds, errors and canonical frame helpers of the KAGEMUSHA wallet V1 root.

use core::ops::Range;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::*;
use crate::nexus::AxtAssetIncarnationValidationError;

/// Byte range of the Norito header checksum (`magic 4, major, minor, schema 16, compression,
/// length 8`, then the checksum).
const HEADER_CHECKSUM: Range<usize> = 31..39;

/// Payload range of one canonical frame (after the header and alignment padding).
pub(super) fn payload_range(frame: &[u8]) -> Range<usize> {
    let header = norito::core::Header::read(frame).expect("canonical header");
    let length = usize::try_from(header.length).expect("bounded test frame");
    let start = frame
        .len()
        .checked_sub(length)
        .expect("payload within frame");
    start..frame.len()
}

/// Flip one byte of a canonical frame. Payload flips also recompute the header checksum, so
/// the mutation reaches the typed decoder instead of stopping at the CRC.
pub(super) fn flip_byte(frame: &[u8], index: usize) -> Vec<u8> {
    let payload = payload_range(frame);
    let mut flipped = frame.to_vec();
    flipped[index] ^= 0x01;
    if payload.contains(&index) {
        let checksum = norito::crc64_fallback(&flipped[payload]);
        flipped[HEADER_CHECKSUM].copy_from_slice(&checksum.to_le_bytes());
    }
    flipped
}

/// Require that flipping any single byte of `frame` either makes `accept` reject it or
/// changes the digest `accept` returns.
pub(super) fn assert_every_flip_rejected_or_rebound(
    frame: &[u8],
    original_digest: [u8; 32],
    accept: impl Fn(&[u8]) -> Option<[u8; 32]>,
) {
    assert_eq!(accept(frame), Some(original_digest), "unmodified frame");
    for index in 0..frame.len() {
        if let Some(digest) = accept(&flip_byte(frame, index)) {
            assert_ne!(
                digest, original_digest,
                "flip at byte {index} kept the digest"
            );
        }
    }
}

/// Norito `u32` wire tag of an enum value.
pub(super) fn norito_tag<T: norito::NoritoSerialize>(value: &T) -> u32 {
    let frame = norito::encode_canonical(value).expect("encode enum");
    let start = payload_range(&frame).start;
    let mut tag = [0; 4];
    tag.copy_from_slice(&frame[start..start + 4]);
    u32::from_le_bytes(tag)
}

#[test]
fn kagemusha_wallet_v1_bounds_match_the_design() {
    assert_eq!(KAGEMUSHA_WALLET_VERSION_V1, 1);
    assert_eq!(KAGEMUSHA_WALLET_TEXT_PREFIX_V1, "kgm1:");
    assert_eq!(KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1, 2_048);
    assert_eq!(KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1, 10_000);
    assert_eq!(KAGEMUSHA_WALLET_SESSION_TEXT_MAX_BYTES_V1, 2_736);
    assert_eq!(KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1, 13_339);
    assert_eq!(KAGEMUSHA_WALLET_CERTIFICATE_SET_MAX_V1, 3);
    for (actual, expected) in [
        (KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1, 512),
        (KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1, 512),
        (KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1, 1_024),
        (KAGEMUSHA_WALLET_SCHEME_POLICY_MAX_BYTES_V1, 1_024),
        (KAGEMUSHA_WALLET_FEE_SCHEDULE_MAX_BYTES_V1, 1_024),
        (KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1, 512),
        (KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1, 262_144),
        (KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1, 1_024),
        (KAGEMUSHA_WALLET_LEDGER_CONTROL_MAX_BYTES_V1, 1_024),
        (KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1, 1_024),
        (KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1, 1_024),
        (KAGEMUSHA_WALLET_QUOTA_SHARE_MAX_BYTES_V1, 8_192),
        (KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1, 16_384),
        (KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1, 16_384),
        (KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1, 16_384),
        (KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1, 16_384),
        (KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1, 1_024),
        (KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1, 73_728),
        (KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1, 65_536),
        (KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1, 524_288),
        (KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1, 10_000),
        (KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1, 2_228_736),
    ] {
        assert_eq!(actual, expected);
    }
}

#[test]
fn kagemusha_wallet_v1_text_bounds_match_unpadded_base64url() {
    for len in 0..=96 {
        assert_eq!(
            unpadded_base64url_len_v1(len),
            URL_SAFE_NO_PAD.encode(vec![0_u8; len]).len(),
            "length {len}"
        );
        assert_eq!(
            text_max_bytes_v1(len),
            KAGEMUSHA_WALLET_TEXT_PREFIX_V1.len() + unpadded_base64url_len_v1(len)
        );
    }
    assert_eq!(
        text_max_bytes_v1(KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1),
        KAGEMUSHA_WALLET_TEXT_PREFIX_V1.len()
            + URL_SAFE_NO_PAD
                .encode(vec![0_u8; KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1])
                .len()
    );
}

#[test]
fn kagemusha_wallet_v1_errors_display_and_convert() {
    let errors = [
        KagemushaWalletValidationErrorV1::Codec(norito::Error::LengthMismatch),
        KagemushaWalletValidationErrorV1::EncodedSizeExceeded {
            actual: 11,
            max: 10,
        },
        KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "scheme.version",
            version: 2,
        },
        KagemushaWalletValidationErrorV1::SchemeMismatch { field: "scheme" },
        KagemushaWalletValidationErrorV1::InvalidField { field: "field" },
        KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: KagemushaWalletSigningDomainV1::Credential,
        },
        KagemushaWalletValidationErrorV1::ArithmeticOverflow { field: "count" },
    ];
    let rendered: Vec<String> = errors.iter().map(ToString::to_string).collect();
    assert!(rendered[1].contains("11") && rendered[1].contains("10"));
    assert!(rendered[2].contains("scheme.version") && rendered[2].contains('2'));
    assert!(rendered[5].contains("kgwcred1"));
    for (index, text) in rendered.iter().enumerate() {
        assert!(text.contains("KAGEMUSHA wallet V1"), "{index}: {text}");
    }
    assert!(std::error::Error::source(&errors[0]).is_some());
    assert!(std::error::Error::source(&errors[4]).is_none());

    assert!(matches!(
        KagemushaWalletValidationErrorV1::from(norito::Error::LengthMismatch),
        KagemushaWalletValidationErrorV1::Codec(norito::Error::LengthMismatch)
    ));
    assert!(matches!(
        KagemushaWalletValidationErrorV1::from(AxtAssetIncarnationValidationError::Zero),
        KagemushaWalletValidationErrorV1::InvalidField {
            field: "asset_incarnation"
        }
    ));
}

#[test]
fn kagemusha_wallet_v1_field_guards() {
    assert!(require_version_v1("v", KAGEMUSHA_WALLET_VERSION_V1).is_ok());
    assert!(matches!(
        require_version_v1("v", 2),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "v",
            version: 2
        })
    ));
    assert!(matches!(
        require_version_v1("v", 0),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
    assert!(is_zero_v1(&[0; 32]));
    assert!(!is_zero_v1(&[0x80; 32]));
    assert!(require_nonzero_v1("d", &[0; 32]).is_err());
    let mut last = [0; 32];
    last[31] = 1;
    assert!(require_nonzero_v1("d", &last).is_ok());
    assert!(require_scheme_v1("s", &[1; 32], &[1; 32]).is_ok());
    assert!(matches!(
        require_scheme_v1("s", &[1; 32], &[2; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { field: "s" })
    ));
    assert!(require_canonical_field_v1("f", &[0; 32]).is_ok());
    assert!(require_canonical_field_v1("f", &last).is_ok());
    assert!(matches!(
        require_canonical_field_v1("f", &KAGEMUSHA_WALLET_FIELD_MODULUS_V1),
        Err(KagemushaWalletValidationErrorV1::InvalidField { field: "f" })
    ));
    assert!(require_nonzero_field_v1("g", &last).is_ok());
    assert!(matches!(
        require_nonzero_field_v1("g", &[0; 32]),
        Err(KagemushaWalletValidationErrorV1::InvalidField { field: "g" })
    ));
    assert!(matches!(
        require_nonzero_field_v1("g", &[0xff; 32]),
        Err(KagemushaWalletValidationErrorV1::InvalidField { field: "g" })
    ));
    assert!(matches!(
        invalid_v1("x"),
        KagemushaWalletValidationErrorV1::InvalidField { field: "x" }
    ));
    assert!(matches!(
        overflow_v1("y"),
        KagemushaWalletValidationErrorV1::ArithmeticOverflow { field: "y" }
    ));
}

#[test]
fn kagemusha_wallet_v1_frames_are_bounded_before_decoding() {
    let value = KagemushaWalletRegulatoryPolicyV1 {
        permitted_controls: KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1,
        blacklist_max_age_ms: 0,
        time_anchor_max_response_ms: 0,
    };
    let frame = encode_frame_v1(&value, 4_096).expect("encode");
    assert_eq!(frame, norito::encode_canonical(&value).expect("canonical"));
    assert!(matches!(
        encode_frame_v1(&value, frame.len() - 1),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
    let decoded: KagemushaWalletRegulatoryPolicyV1 =
        decode_frame_v1(&frame, frame.len()).expect("decode at the exact cap");
    assert_eq!(decoded, value);

    // The cap is enforced before any byte is parsed.
    let garbage = vec![0xff_u8; 17];
    assert!(matches!(
        decode_frame_v1::<KagemushaWalletRegulatoryPolicyV1>(&garbage, 16),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded {
            actual: 17,
            max: 16
        })
    ));
    assert!(matches!(
        decode_frame_v1::<KagemushaWalletRegulatoryPolicyV1>(&garbage, 17),
        Err(KagemushaWalletValidationErrorV1::Codec(_))
    ));
    let mut extended = frame.clone();
    extended.push(0);
    assert!(decode_frame_v1::<KagemushaWalletRegulatoryPolicyV1>(&extended, 4_096).is_err());
    assert!(
        decode_frame_v1::<KagemushaWalletRegulatoryPolicyV1>(&frame[..frame.len() - 1], 4_096)
            .is_err()
    );
}

#[test]
fn kagemusha_wallet_v1_flip_helper_recomputes_the_payload_checksum() {
    let frame =
        norito::encode_canonical(&KagemushaWalletRegulatoryPolicyV1::default()).expect("encode");
    let payload = payload_range(&frame);
    let flipped = flip_byte(&frame, payload.start);
    let header = norito::core::Header::read(flipped.as_slice()).expect("header");
    assert_eq!(
        header.checksum,
        norito::crc64_fallback(&flipped[payload.clone()])
    );
    assert_ne!(flipped[payload.start], frame[payload.start]);
    let header_flip = flip_byte(&frame, 0);
    assert_eq!(header_flip[HEADER_CHECKSUM], frame[HEADER_CHECKSUM]);
    assert_eq!(norito_tag(&KagemushaWalletSignerRoleV1::Artifact), 5);
}
