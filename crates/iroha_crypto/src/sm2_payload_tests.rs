//! Borrowed distinguishing identifiers and canonical SM2 payload boundaries.

use super::*;

fn payload(distid: &str, material: &[u8]) -> Vec<u8> {
    let mut result = u16::try_from(distid.len()).unwrap().to_be_bytes().to_vec();
    result.extend_from_slice(distid.as_bytes());
    result.extend_from_slice(material);
    result
}

#[test]
fn split_borrows_exact_empty_unicode_and_maximum_identifiers() {
    for distid in [String::new(), "署名者-é".into(), "a".repeat(8191)] {
        let bytes = payload(&distid, &[0x51; 65]);
        let (borrowed, material) = split_sm2_payload(&bytes).unwrap();
        assert_eq!(borrowed, distid);
        assert_eq!(borrowed.as_ptr(), bytes[2..].as_ptr());
        assert_eq!(material, &[0x51; 65]);
        assert_eq!(material.as_ptr(), bytes[2 + distid.len()..].as_ptr());
    }
}

#[test]
fn split_preserves_validation_precedence_and_exact_errors() {
    for bytes in [&[][..], &[0x01][..]] {
        assert_eq!(
            split_sm2_payload(bytes).unwrap_err(),
            ParseError::Invalid("SM2 payload missing distid length prefix".into())
        );
    }
    assert_eq!(
        split_sm2_payload(&[0x00, 0x02, 0xff]).unwrap_err(),
        ParseError::Invalid("SM2 payload truncated distid".into())
    );
    assert_eq!(
        split_sm2_payload(&[0x00, 0x01, 0xff]).unwrap_err(),
        ParseError::Invalid("SM2 distid must be valid UTF-8".into())
    );
    assert_eq!(
        split_sm2_payload(&payload(&"a".repeat(8192), &[])).unwrap_err(),
        ParseError::Invalid("SM2 distinguishing identifier exceeds 65535 bits".into())
    );
}

#[test]
fn public_payload_keeps_canonical_uncompressed_point_and_identifier() {
    let distid = "署名者-é";
    let private = Sm2PrivateKey::from_seed(distid, b"borrowed public envelope").unwrap();
    let public = private.public_key();
    let raw = public.to_sec1_bytes(false);
    let envelope = payload(distid, &raw);
    let decoded = decode_sm2_public_key_payload(&envelope).unwrap();
    assert_eq!(decoded, public);
    assert_eq!(decoded.distid(), distid);
    assert_eq!(decoded.to_sec1_bytes(false), raw);
    let signature = private.sign(b"canonical message");
    decoded.verify(b"canonical message", &signature).unwrap();

    let compressed = payload(distid, &public.to_sec1_bytes(true));
    assert_eq!(
        decode_sm2_public_key_payload(&compressed).unwrap_err(),
        ParseError::Invalid("SM2 public key payload must be 65 bytes".into())
    );
    let mut extra = envelope;
    extra.push(0);
    assert_eq!(
        decode_sm2_public_key_payload(&extra).unwrap_err(),
        ParseError::Invalid("SM2 public key payload must be 65 bytes".into())
    );
    assert!(decode_sm2_public_key_payload(&payload(distid, &[0; 65])).is_err());
}

#[test]
fn private_payload_retains_owned_identity_after_borrowed_envelope_drops() {
    let distid = "署名者-é";
    let original = Sm2PrivateKey::from_seed(distid, b"borrowed private envelope").unwrap();
    let secret = original.secret_bytes();
    let decoded = {
        let envelope = payload(distid, &secret);
        decode_sm2_private_key_payload(&envelope).unwrap()
    };
    assert_eq!(decoded.distid(), distid);
    assert_eq!(decoded.secret_bytes(), secret);
    assert_eq!(decoded.public_key(), original.public_key());
    for material in [&secret[..31], &[0; 33][..]] {
        assert_eq!(
            decode_sm2_private_key_payload(&payload(distid, material))
                .err()
                .expect("wrong private material length must fail"),
            ParseError::Invalid("SM2 private key payload must be 32 bytes".into())
        );
    }
    assert_eq!(
        decode_sm2_private_key_payload(&payload(distid, &[0; 32]))
            .err()
            .expect("zero private material must fail"),
        ParseError::Invalid("SM2 private key material must not be all zero".into())
    );
}
