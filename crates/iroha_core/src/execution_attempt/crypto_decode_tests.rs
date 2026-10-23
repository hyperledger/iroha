//! Exact unavailable-parser deferral without relabeling malformed or resource errors.

use super::*;
use iroha_crypto::{Algorithm, CryptoOperation};

#[test]
fn only_an_actually_unavailable_canonical_parser_is_deferred() {
    for &algorithm in Algorithm::ALL {
        let error = norito::Error::UnsupportedFeature(algorithm.as_static_str());
        let actual = crypto_public_key_decode_deferred(&error);
        match algorithm.require_implementation(CryptoOperation::ParsePublicKey) {
            Ok(()) => assert!(actual.is_none()),
            Err(original) => assert_eq!(
                actual.unwrap().reason(),
                ExecutionDeferral::CryptoImplementationUnavailable(original)
            ),
        }
    }
    for error in [
        norito::Error::UnsupportedFeature("unknown-cryptographic-algorithm"),
        norito::Error::UnsupportedFeature("Ed25519"),
        norito::Error::LengthMismatch,
        norito::Error::AllocationFailed { bytes: 17 },
    ] {
        assert!(crypto_public_key_decode_deferred(&error).is_none());
    }
}

#[test]
fn actual_gost_key_decoder_preserves_actual_parser_outcome() {
    use iroha_crypto::PublicKey;
    let algorithm = Algorithm::Gost3410_2012_256ParamSetA;
    let key =
        hex::decode(include_str!("../../../../fixtures/account/gost256a_public_key.hex").trim())
            .unwrap();
    let decoded = PublicKey::from_bytes_for_decode(algorithm, &key);
    match algorithm.require_implementation(CryptoOperation::ParsePublicKey) {
        Ok(()) => {
            let decoded =
                decoded.expect("available GOST parser accepts the original valid fixture");
            assert_eq!(decoded.try_to_bytes().unwrap(), (algorithm, key.as_slice()));
            eprintln!("actual GOST parser: available; exact original fixture decoded");
        }
        Err(original) => {
            let error = decoded.unwrap_err();
            assert!(matches!(&error, norito::Error::UnsupportedFeature(name)
                if *name == algorithm.as_static_str()));
            let deferred = crypto_public_key_decode_deferred(&error).unwrap();
            assert_eq!(
                deferred.reason(),
                ExecutionDeferral::CryptoImplementationUnavailable(original)
            );
            assert!(deferred.decode_refusal().is_none());
            assert!(deferred.allocation_refusal().is_none());
            eprintln!("actual GOST parser: absent; original backend identity deferred");
        }
    }
}
