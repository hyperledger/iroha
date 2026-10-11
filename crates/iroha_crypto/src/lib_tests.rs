// Crypto crate regressions are included at crate scope to preserve private-item access.
#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::{Decode, Encode};
    use zeroize::Zeroizing;
    static SESSION_KEY_ZEROIZATION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn session_key_zeroization_test_guard() -> std::sync::MutexGuard<'static, ()> {
        SESSION_KEY_ZEROIZATION_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn supported_algorithms() -> Vec<Algorithm> {
        let base = [Algorithm::Ed25519, Algorithm::Secp256k1];
        #[cfg(feature = "gost")]
        let gost_algorithms = [
            Algorithm::Gost3410_2012_256ParamSetA,
            Algorithm::Gost3410_2012_256ParamSetB,
            Algorithm::Gost3410_2012_256ParamSetC,
            Algorithm::Gost3410_2012_512ParamSetA,
            Algorithm::Gost3410_2012_512ParamSetB,
        ];
        #[cfg(not(feature = "gost"))]
        let gost_algorithms: [Algorithm; 0] = [];
        #[cfg(feature = "pqc")]
        let ml_dsa_algorithms = [Algorithm::MlDsa];
        #[cfg(not(feature = "pqc"))]
        let ml_dsa_algorithms: [Algorithm; 0] = [];
        #[cfg(feature = "bls")]
        let bls_algorithms = [Algorithm::BlsNormal, Algorithm::BlsSmall];
        #[cfg(not(feature = "bls"))]
        let bls_algorithms: [Algorithm; 0] = [];
        #[cfg(feature = "sm")]
        let sm_algorithms = [Algorithm::Sm2];
        #[cfg(not(feature = "sm"))]
        let sm_algorithms: [Algorithm; 0] = [];
        base.iter()
            .chain(gost_algorithms.iter())
            .chain(ml_dsa_algorithms.iter())
            .chain(bls_algorithms.iter())
            .chain(sm_algorithms.iter())
            .copied()
            .collect()
    }
    #[cfg(feature = "pqc")]
    #[derive(Debug)]
    struct FailingTryRngError;
    #[cfg(feature = "pqc")]
    impl core::fmt::Display for FailingTryRngError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("failing ML-DSA signing RNG")
        }
    }
    #[cfg(feature = "pqc")]
    struct FailingTryRng;
    #[cfg(feature = "pqc")]
    impl rand_core::TryRngCore for FailingTryRng {
        type Error = FailingTryRngError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(FailingTryRngError)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(FailingTryRngError)
        }
        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Self::Error> {
            Err(FailingTryRngError)
        }
    }
    #[cfg(feature = "pqc")]
    impl rand_core::TryCryptoRng for FailingTryRng {}
    #[cfg(feature = "pqc")]
    struct FixedTryRng {
        byte: u8,
    }
    #[cfg(feature = "pqc")]
    impl rand_core::TryRngCore for FixedTryRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes([self.byte; 4]))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes([self.byte; 8]))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            dest.fill(self.byte);
            Ok(())
        }
    }
    #[cfg(feature = "pqc")]
    impl rand_core::TryCryptoRng for FixedTryRng {}
    #[cfg(feature = "pqc")]
    fn seeded_ml_dsa_secret(seed: &[u8]) -> (PublicKey, MlDsaSecretKey) {
        use pqcrypto_traits::sign::SecretKey as _;
        let (public, private) =
            mldsa_seed::mldsa65::keypair_from_seed(seed).expect("seeded ML-DSA keypair");
        let raw_secret = pqcrypto_mldsa::mldsa65::SecretKey::from_bytes(&private.to_bytes().1)
            .expect("valid ML-DSA secret bytes");
        (public, MlDsaSecretKey::new(&raw_secret))
    }
    fn checked_seed_keypair(seed: &[u8], algorithm: Algorithm) -> KeyPair {
        KeyPair::try_from_seed(seed.to_vec(), algorithm).expect("generate checked seeded keypair")
    }
    #[cfg(feature = "rand")]
    fn checked_random_keypair(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm).expect("generate checked random keypair")
    }
    fn checked_signature(private_key: &PrivateKey, message: &[u8]) -> Signature {
        Signature::try_new(private_key, message).expect("sign checked top-level fixture")
    }
    #[test]
    fn ed25519_parse_signature_rejects_inert_or_malformed_r() {
        const SMALL_ORDER_R: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_R: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let key_pair = checked_seed_keypair(&[0x31; 32], Algorithm::Ed25519);
        let signature = checked_signature(key_pair.private_key(), b"ed25519 parse signature");
        ed25519_parse_signature(signature.payload()).expect("valid Ed25519 signature parses");
        let err = ed25519_parse_signature(&[0u8; 64])
            .expect_err("all-zero Ed25519 signature material must fail admission");
        assert!(
            matches!(err, Error::Parse(ref parse) if parse.to_string().contains("all zero")),
            "unexpected all-zero signature error: {err:?}"
        );
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut malformed = signature.payload().to_vec();
            malformed[..32].copy_from_slice(&replacement_r);
            let err = ed25519_parse_signature(&malformed)
                .expect_err("malformed Ed25519 signature R must fail admission");
            assert_eq!(
                err,
                Error::BadSignature,
                "{label} R should fail as a bad Ed25519 signature"
            );
        }
    }
    #[cfg(feature = "pqc")]
    #[test]
    fn mldsa_shared_verifier_preserves_signature_and_batch_admission() {
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
        let keypair = checked_seed_keypair(&[0x53; 32], Algorithm::MlDsa);
        let message = b"ML-DSA shared verifier admission";
        let signature = checked_signature(keypair.private_key(), message);
        let (_, public_key) = keypair.public_key().try_to_bytes().unwrap();
        let typed_key = pqcrypto_mldsa::mldsa65::PublicKey::from_bytes(public_key).unwrap();
        let typed_signature =
            pqcrypto_mldsa::mldsa65::DetachedSignature::from_bytes(signature.payload()).unwrap();
        verify_mldsa65_detached(&typed_signature, message, &typed_key)
            .expect("shared typed verifier");
        signature
            .verify(keypair.public_key(), message)
            .expect("single verification");
        verify_signature_for_admission(&signature, keypair.public_key(), message)
            .expect("admission verification");
        assert!(matches!(
            verify_signature_for_admission(&signature, keypair.public_key(), b"changed"),
            Err(Error::BadSignature),
        ));
        let different_keypair = checked_seed_keypair(&[0x56; 32], Algorithm::MlDsa);
        assert!(matches!(
            verify_signature_for_admission(&signature, different_keypair.public_key(), message),
            Err(Error::BadSignature),
        ));
        pqc_verify_batch_deterministic(&[message], &[signature.payload()], &[public_key], [0; 32])
            .expect("batch verification");
        assert!(matches!(
            signature.verify(keypair.public_key(), b"changed"),
            Err(Error::BadSignature),
        ));
        assert!(matches!(
            pqc_verify_batch_deterministic(
                &[b"changed"],
                &[signature.payload()],
                &[public_key],
                [0; 32],
            ),
            Err(Error::BadSignature),
        ));
        let mut corrupt = signature.payload().to_vec();
        corrupt[0] ^= 1;
        let mut overlong = signature.payload().to_vec();
        overlong.push(1);
        for invalid in [
            corrupt,
            signature.payload()[1..].to_vec(),
            overlong,
            vec![0; signature.payload().len()],
        ] {
            assert!(matches!(
                verify_signature_for_admission(
                    &Signature::from_bytes(&invalid),
                    keypair.public_key(),
                    message,
                ),
                Err(Error::BadSignature),
            ));
            assert!(matches!(
                Signature::from_bytes(&invalid).verify(keypair.public_key(), message),
                Err(Error::BadSignature),
            ));
            assert!(matches!(
                pqc_verify_batch_deterministic(&[message], &[&invalid], &[public_key], [0; 32]),
                Err(Error::BadSignature),
            ));
        }
        for invalid_key in [public_key[1..].to_vec(), vec![0; public_key.len()]] {
            assert!(matches!(
                pqc_verify_batch_deterministic(
                    &[message],
                    &[signature.payload()],
                    &[&invalid_key],
                    [0; 32],
                ),
                Err(Error::BadSignature),
            ));
        }
        let wrong_algorithm = checked_seed_keypair(&[0x54; 32], Algorithm::Ed25519);
        assert!(
            signature
                .verify(wrong_algorithm.public_key(), message)
                .is_err()
        );
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn mldsa65_parse_signature_rejects_inert_or_malformed_lengths() {
        let key_pair = checked_seed_keypair(&[0x32; 32], Algorithm::MlDsa);
        let signature = checked_signature(key_pair.private_key(), b"mldsa65 parse signature");
        mldsa65_parse_signature(signature.payload()).expect("valid ML-DSA-65 signature parses");
        let err = mldsa65_parse_signature(&[0u8; 64])
            .expect_err("all-zero ML-DSA signature material must fail admission");
        assert!(
            matches!(err, Error::Parse(ref parse) if parse.to_string().contains("all zero")),
            "unexpected all-zero signature error: {err:?}"
        );
        let mut short = signature.payload().to_vec();
        short.pop().expect("ML-DSA signature fixture is non-empty");
        let mut overlong = signature.payload().to_vec();
        overlong.push(0xA5);
        for (label, malformed) in [("short", short), ("overlong", overlong)] {
            let err = mldsa65_parse_signature(&malformed)
                .expect_err("malformed ML-DSA-65 signature length must fail admission");
            assert_eq!(
                err,
                Error::BadSignature,
                "{label} ML-DSA-65 signature should fail as a bad signature"
            );
        }
    }
    #[test]
    fn session_key_from_zeroizing_vec_preserves_payload_and_zeroizes_on_drop() {
        let _test_guard = session_key_zeroization_test_guard();
        __debug_clear_last_zeroized_session_key();
        let expected = vec![0x7B; 32];
        {
            let session_key = SessionKey::from_zeroizing_vec(Zeroizing::new(expected.clone()));
            assert_eq!(session_key.payload(), expected.as_slice());
        }
        let recorded = __debug_last_zeroized_session_key();
        assert_eq!(recorded.len(), expected.len());
        assert!(recorded.iter().all(|&byte| byte == 0));
    }
    #[test]
    fn session_key_zeroization_log_recovers_from_poisoned_debug_mutex() {
        let _test_guard = session_key_zeroization_test_guard();
        let result = std::panic::catch_unwind(|| {
            let _guard = session_key_zeroization_log()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("poison session-key zeroization debug log");
        });
        assert!(result.is_err());
        let expected = vec![0x3C; 24];
        {
            let session_key = SessionKey::new(expected.clone());
            assert_eq!(session_key.payload(), expected.as_slice());
        }
        let recorded = __debug_last_zeroized_session_key();
        assert_eq!(recorded.len(), expected.len());
        assert!(recorded.iter().all(|&byte| byte == 0));
    }
    #[test]
    fn private_key_try_to_bytes_roundtrips_classic_payloads() {
        let cases: &[(Algorithm, &[u8])] = &[
            (Algorithm::Ed25519, b"iroha:ed25519-private-export"),
            (Algorithm::Secp256k1, b"iroha:secp256k1-private-export"),
        ];
        for (algorithm, seed) in cases {
            let key_pair = checked_seed_keypair(seed, *algorithm);
            let (exported_algorithm, payload) = key_pair
                .private_key()
                .try_to_bytes()
                .expect("private key payload exports");
            assert_eq!(exported_algorithm, *algorithm);
            assert!(
                !payload.is_empty(),
                "{algorithm:?} private-key export must not be empty"
            );
            let parsed = PrivateKey::from_bytes(exported_algorithm, &payload)
                .expect("exported private key payload parses");
            assert_eq!(parsed.to_bytes(), (exported_algorithm, payload));
            let message = b"top-level private-key export roundtrip";
            let signature = checked_signature(&parsed, message);
            signature
                .verify(key_pair.public_key(), message)
                .expect("reparsed private key signs for original public key");
        }
    }
    #[test]
    #[cfg(feature = "bls")]
    fn private_key_try_to_bytes_roundtrips_bls_payloads() {
        let cases: &[(Algorithm, &[u8])] = &[
            (Algorithm::BlsNormal, b"iroha:bls-normal-private-export"),
            (Algorithm::BlsSmall, b"iroha:bls-small-private-export"),
        ];
        for (algorithm, seed) in cases {
            let key_pair =
                KeyPair::try_from_seed(seed.to_vec(), *algorithm).expect("seeded BLS keypair");
            let (exported_algorithm, payload) = key_pair
                .private_key()
                .try_to_bytes()
                .expect("private key payload exports");
            assert_eq!(exported_algorithm, *algorithm);
            assert!(
                !payload.is_empty(),
                "{algorithm:?} private-key export must not be empty"
            );
            let parsed = PrivateKey::from_bytes(exported_algorithm, &payload)
                .expect("exported BLS private key payload parses");
            assert_eq!(parsed.to_bytes(), (exported_algorithm, payload));
            let message = b"top-level BLS private-key export roundtrip";
            let signature = Signature::try_new(&parsed, message).expect("BLS signature");
            signature
                .verify(key_pair.public_key(), message)
                .expect("reparsed BLS private key signs for original public key");
        }
    }
    #[test]
    fn algorithm_serialize_deserialize_consistent() {
        for algorithm in supported_algorithms() {
            let ser = norito::json::to_json(&algorithm)
                .unwrap_or_else(|_| panic!("Failed to serialize algorithm {:?}", &algorithm));
            let de: Algorithm = norito::json::from_str(&ser)
                .unwrap_or_else(|_| panic!("Failed to deserialize algorithm {:?}", &algorithm));
            assert_eq!(algorithm, de);
        }
    }
    #[test]
    #[cfg(feature = "rand")]
    fn try_random_with_algorithm_ed25519_signs_and_verifies() {
        let key_pair = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("checked Ed25519 random keypair");
        let wrong_key = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("checked wrong Ed25519 random keypair");
        let message = b"top-level checked Ed25519 random keypair";
        let signature = checked_signature(key_pair.private_key(), message);
        signature
            .verify(key_pair.public_key(), message)
            .expect("signature verifies");
        signature
            .verify(wrong_key.public_key(), message)
            .expect_err("signature must reject wrong Ed25519 key");
    }
    #[test]
    #[cfg(feature = "rand")]
    fn try_random_with_algorithm_secp256k1_signs_and_verifies() {
        let key_pair = KeyPair::try_random_with_algorithm(Algorithm::Secp256k1)
            .expect("checked secp256k1 random keypair");
        let wrong_key = KeyPair::try_random_with_algorithm(Algorithm::Secp256k1)
            .expect("checked wrong secp256k1 random keypair");
        let message = b"top-level checked secp256k1 random keypair";
        let signature = checked_signature(key_pair.private_key(), message);
        signature
            .verify(key_pair.public_key(), message)
            .expect("signature verifies");
        signature
            .verify(wrong_key.public_key(), message)
            .expect_err("signature must reject wrong secp256k1 key");
    }

    #[test]
    fn admission_verifier_preserves_ed25519_and_secp256k1_verdicts() {
        for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1] {
            let key_pair = checked_seed_keypair(&[algorithm as u8 + 0x31; 32], algorithm);
            let wrong_key = checked_seed_keypair(&[algorithm as u8 + 0x51; 32], algorithm);
            let message = b"cache-free admission signature";
            let proof = checked_signature(key_pair.private_key(), message);
            verify_signature_for_admission(&proof, key_pair.public_key(), message)
                .expect("admission signature verifies");
            verify_signature_for_admission(&proof, wrong_key.public_key(), message)
                .expect_err("admission verifier rejects the wrong key");
            verify_signature_for_admission(&proof, key_pair.public_key(), b"tampered")
                .expect_err("admission verifier rejects a changed message");
        }
    }
    #[test]
    #[cfg(all(feature = "rand", feature = "pqc"))]
    fn try_random_with_algorithm_ml_dsa_signs_and_verifies() {
        let key_pair = KeyPair::try_random_with_algorithm(Algorithm::MlDsa)
            .expect("checked ML-DSA random keypair");
        let wrong_key = KeyPair::try_random_with_algorithm(Algorithm::MlDsa)
            .expect("checked wrong ML-DSA random keypair");
        let message = b"top-level checked ML-DSA random keypair";
        let signature = checked_signature(key_pair.private_key(), message);
        signature
            .verify(key_pair.public_key(), message)
            .expect("signature verifies");
        signature
            .verify(wrong_key.public_key(), message)
            .expect_err("signature must reject wrong ML-DSA key");
    }
    #[cfg(feature = "sm")]
    #[test]
    #[cfg(feature = "rand")]
    fn try_random_with_algorithm_sm2_signs_and_verifies() {
        let key_pair =
            KeyPair::try_random_with_algorithm(Algorithm::Sm2).expect("checked SM2 random keypair");
        let wrong_key = KeyPair::try_random_with_algorithm(Algorithm::Sm2)
            .expect("checked wrong SM2 random keypair");
        let message = b"top-level checked SM2 random keypair";
        let signature = checked_signature(key_pair.private_key(), message);
        signature
            .verify(key_pair.public_key(), message)
            .expect("signature verifies");
        signature
            .verify(wrong_key.public_key(), message)
            .expect_err("signature must reject wrong SM2 key");
    }
    #[cfg(feature = "sm")]
    #[test]
    fn try_from_seed_sm2_uses_checked_public_derivation() {
        let key_pair = KeyPair::try_from_seed(vec![0x53; 32], Algorithm::Sm2)
            .expect("checked SM2 seeded keypair");
        let derived_public = PublicKey::from_private_key(key_pair.private_key())
            .expect("checked SM2 public derivation");
        assert_eq!(derived_public, key_pair.public_key().clone());
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn try_from_seed_ml_dsa_is_deterministic_and_signs() {
        let seed = b"iroha:top-level-ml-dsa-seed";
        let first = KeyPair::try_from_seed(seed.to_vec(), Algorithm::MlDsa)
            .expect("checked ML-DSA seeded keypair");
        let second = KeyPair::try_from_seed(seed.to_vec(), Algorithm::MlDsa)
            .expect("checked ML-DSA seeded keypair");
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(
            first.private_key().to_bytes(),
            second.private_key().to_bytes()
        );
        let message = b"top-level checked ML-DSA seeded keypair";
        let signature = checked_signature(first.private_key(), message);
        signature
            .verify(first.public_key(), message)
            .expect("signature verifies");
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn try_from_seed_ml_dsa_rejects_empty_seed_material() {
        match KeyPair::try_from_seed(Vec::new(), Algorithm::MlDsa) {
            Err(Error::KeyGen(message)) => assert!(message.contains("empty")),
            Err(err) => panic!("expected empty seed KeyGen error, got {err:?}"),
            Ok(_) => panic!("empty ML-DSA seed material must fail"),
        }
    }
    #[cfg(feature = "gost")]
    #[test]
    fn try_from_seed_gost_is_deterministic_and_signs() {
        let seed = b"iroha:top-level-gost-seed";
        let first = KeyPair::try_from_seed(seed.to_vec(), Algorithm::Gost3410_2012_256ParamSetB)
            .expect("checked GOST seeded keypair");
        let second = KeyPair::try_from_seed(seed.to_vec(), Algorithm::Gost3410_2012_256ParamSetB)
            .expect("checked GOST seeded keypair");
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(
            first.private_key().to_bytes(),
            second.private_key().to_bytes()
        );
        let message = b"top-level checked GOST seeded keypair";
        let signature =
            Signature::try_new(first.private_key(), message).expect("checked GOST signature");
        signature
            .verify(first.public_key(), message)
            .expect("signature verifies");
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_normal_aggregate_fast_accepts_valid_and_rejects_bad() {
        let msg = b"bls-normal-fast";
        let kp1 = checked_seed_keypair(&[1; 32], Algorithm::BlsNormal);
        let kp2 = checked_seed_keypair(&[2; 32], Algorithm::BlsNormal);
        let (pk1, sk1) = kp1.into_parts();
        let (pk2, sk2) = kp2.into_parts();
        let sig1 = checked_signature(&sk1, msg);
        let sig2 = checked_signature(&sk2, msg);
        let signatures: Vec<&[u8]> = vec![sig1.payload(), sig2.payload()];
        let public_keys: Vec<&PublicKey> = vec![&pk1, &pk2];
        let pops = [
            bls_normal_pop_prove(&sk1).expect("pop"),
            bls_normal_pop_prove(&sk2).expect("pop"),
        ];
        let pop_refs: Vec<&[u8]> = pops.iter().map(Vec::as_slice).collect();
        bls_normal_verify_aggregate_same_message_fast(msg, &signatures, &public_keys, &pop_refs)
            .expect("aggregate fast ok");
        let mut bad_sig = sig1.payload().to_vec();
        bad_sig[0] ^= 0x01;
        let bad_signatures: Vec<&[u8]> = vec![bad_sig.as_slice(), sig2.payload()];
        assert!(
            bls_normal_verify_aggregate_same_message_fast(
                msg,
                &bad_signatures,
                &public_keys,
                &pop_refs,
            )
            .is_err(),
            "bad signature must be rejected"
        );
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_normal_same_message_wrappers_reject_duplicate_public_keys() {
        let msg = b"bls-normal-duplicate-public-key";
        let key_pair = checked_seed_keypair(&[9; 32], Algorithm::BlsNormal);
        let (public_key, private_key) = key_pair.into_parts();
        let signature = checked_signature(&private_key, msg);
        let signatures: Vec<&[u8]> = vec![signature.payload(), signature.payload()];
        let public_keys: Vec<&PublicKey> = vec![&public_key, &public_key];
        let pop = bls_normal_pop_prove(&private_key).expect("pop");
        let pops: Vec<&[u8]> = vec![pop.as_slice(), pop.as_slice()];
        assert!(
            bls_normal_verify_aggregate_same_message(msg, &signatures, &public_keys, &pops)
                .is_err(),
            "duplicate signer keys must be rejected in fallback wrapper"
        );
        assert!(
            bls_normal_verify_aggregate_same_message_fast(msg, &signatures, &public_keys, &pops)
                .is_err(),
            "duplicate signer keys must be rejected in fast wrapper"
        );
        assert!(
            bls_normal_verify_preaggregated_same_message(
                msg,
                signature.payload(),
                &public_keys,
                &pops,
            )
            .is_err(),
            "duplicate signer keys must be rejected in preaggregated wrapper"
        );
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_normal_same_message_rejects_canceling_key_aggregate_with_valid_pops() {
        use w3f_bls::SerializableToBytes as _;
        let secret =
            w3f_bls::SecretKeyVT::<w3f_bls::ZBLS>::from_seed(b"iroha:test:canceling-bls-normal");
        let opposite = w3f_bls::SecretKeyVT::<w3f_bls::ZBLS>(-secret.0);
        let sk1 =
            PrivateKey::from_bytes(Algorithm::BlsNormal, &secret.to_bytes()).expect("secret key");
        let sk2 = PrivateKey::from_bytes(Algorithm::BlsNormal, &opposite.to_bytes())
            .expect("opposite secret key");
        let pk1 = PublicKey::from(sk1.clone());
        let pk2 = PublicKey::from(sk2.clone());
        let pop1 = bls_normal_pop_prove(&sk1).expect("pop 1");
        let pop2 = bls_normal_pop_prove(&sk2).expect("pop 2");
        bls_normal_pop_verify(&pk1, &pop1).expect("pop 1 verifies");
        bls_normal_pop_verify(&pk2, &pop2).expect("pop 2 verifies");
        let msg = b"canceling-wrapper-normal";
        let sig1 = checked_signature(&sk1, msg);
        let sig2 = checked_signature(&sk2, msg);
        sig1.verify(&pk1, msg).expect("signature 1 verifies");
        sig2.verify(&pk2, msg).expect("signature 2 verifies");
        let signatures: Vec<&[u8]> = vec![sig1.payload(), sig2.payload()];
        let public_keys: Vec<&PublicKey> = vec![&pk1, &pk2];
        let pop_refs: Vec<&[u8]> = vec![pop1.as_slice(), pop2.as_slice()];
        assert!(
            bls_normal_verify_aggregate_same_message_fast(
                msg,
                &signatures,
                &public_keys,
                &pop_refs
            )
            .is_err(),
            "fast aggregate wrapper must reject identity aggregate"
        );
        assert!(
            bls_normal_verify_aggregate_same_message(msg, &signatures, &public_keys, &pop_refs)
                .is_err(),
            "fallback wrapper must not bypass identity aggregate rejection"
        );
    }
    /// `n` BLS-normal key pairs with their `PoP`-verified public keys.
    #[cfg(feature = "bls")]
    fn pop_verified_keys(n: u8) -> Vec<(BlsNormalPopVerifiedKey, PrivateKey)> {
        (0..n)
            .map(|i| {
                let (pk, sk) =
                    checked_seed_keypair(&[0x40 + i; 32], Algorithm::BlsNormal).into_parts();
                let pop = bls_normal_pop_prove(&sk).expect("pop");
                (
                    BlsNormalPopVerifiedKey::new(&pk, &pop).expect("pop verifies"),
                    sk,
                )
            })
            .collect()
    }
    /// The aggregate of every key of every group signing its group's message.
    #[cfg(feature = "bls")]
    fn multi_message_aggregate(groups: &[(&[&PrivateKey], &[u8])]) -> Vec<u8> {
        let signatures: Vec<Signature> = groups
            .iter()
            .flat_map(|(keys, message)| keys.iter().map(|sk| checked_signature(sk, message)))
            .collect();
        let payloads: Vec<&[u8]> = signatures.iter().map(Signature::payload).collect();
        bls_normal_aggregate_signatures(&payloads).expect("aggregate")
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_normal_preaggregated_multi_message_accepts_valid_groups() {
        let keys = pop_verified_keys(5);
        let (k, s): (Vec<&BlsNormalPopVerifiedKey>, Vec<&PrivateKey>) =
            keys.iter().map(|(k, s)| (k, s)).unzip();
        let (m0, m1, m2) = (
            &b"timeout hq=none"[..],
            &b"timeout hq=3"[..],
            &b"timeout hq=4"[..],
        );
        let agg = multi_message_aggregate(&[(&s[0..2], m0), (&s[2..4], m1), (&s[4..5], m2)]);
        bls_normal_verify_preaggregated_multi_message(
            &[(&k[0..2], m0), (&k[2..4], m1), (&k[4..5], m2)],
            &agg,
        )
        .expect("valid multi-message aggregate");
        // Group order does not matter; one group is the same-message case.
        bls_normal_verify_preaggregated_multi_message(
            &[(&k[4..5], m2), (&k[0..2], m0), (&k[2..4], m1)],
            &agg,
        )
        .expect("groups in another order");
        let same = multi_message_aggregate(&[(&s[..], m0)]);
        bls_normal_verify_preaggregated_multi_message(&[(&k[..], m0)], &same).expect("one group");
        let pks: Vec<&PublicKey> = k.iter().map(|key| key.public_key()).collect();
        let pops: Vec<Vec<u8>> = s
            .iter()
            .map(|sk| bls_normal_pop_prove(sk).expect("pop"))
            .collect();
        let pop_refs: Vec<&[u8]> = pops.iter().map(Vec::as_slice).collect();
        bls_normal_verify_preaggregated_same_message(m0, &same, &pks, &pop_refs)
            .expect("agrees with the same-message primitive");
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_normal_preaggregated_multi_message_rejects_wrong_message_or_group() {
        let keys = pop_verified_keys(4);
        let (k, s): (Vec<&BlsNormalPopVerifiedKey>, Vec<&PrivateKey>) =
            keys.iter().map(|(k, s)| (k, s)).unzip();
        let (m0, m1) = (&b"message zero"[..], &b"message one"[..]);
        let agg = multi_message_aggregate(&[(&s[0..2], m0), (&s[2..4], m1)]);
        let verify = |groups: &[(&[&BlsNormalPopVerifiedKey], &[u8])]| {
            bls_normal_verify_preaggregated_multi_message(groups, &agg)
        };
        assert!(verify(&[(&k[0..2], m0), (&k[2..4], m1)]).is_ok());
        // Wrong message.
        assert!(verify(&[(&k[0..2], m0), (&k[2..4], b"message two")]).is_err());
        assert!(verify(&[(&k[0..2], m1), (&k[2..4], m0)]).is_err());
        // Wrong group: a signer moved to the other message, or missing, or added.
        let moved_a = [k[0], k[1], k[2]];
        let moved_b = [k[3]];
        assert!(verify(&[(&moved_a, m0), (&moved_b, m1)]).is_err());
        assert!(verify(&[(&k[0..1], m0), (&k[2..4], m1)]).is_err());
        assert!(verify(&[(&k[0..2], m0), (&k[1..4], m1)]).is_err());
        // A group is missing.
        assert!(verify(&[(&k[0..2], m0)]).is_err());
        // A tampered signature.
        let mut bad = agg.clone();
        bad[5] ^= 0x01;
        assert!(
            bls_normal_verify_preaggregated_multi_message(&[(&k[0..2], m0), (&k[2..4], m1)], &bad)
                .is_err()
        );
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_normal_preaggregated_multi_message_rejects_empty_and_malformed_input() {
        let keys = pop_verified_keys(3);
        let (k, s): (Vec<&BlsNormalPopVerifiedKey>, Vec<&PrivateKey>) =
            keys.iter().map(|(k, s)| (k, s)).unzip();
        let (m0, m1) = (&b"zero"[..], &b"one"[..]);
        let agg = multi_message_aggregate(&[(&s[0..2], m0), (&s[2..3], m1)]);
        // No group; an empty group.
        assert!(bls_normal_verify_preaggregated_multi_message(&[], &agg).is_err());
        assert!(
            bls_normal_verify_preaggregated_multi_message(
                &[(&k[0..2], m0), (&k[2..3], m1), (&[], b"empty")],
                &agg
            )
            .is_err()
        );
        // A message shared by two groups; a key twice in a group.
        let one = multi_message_aggregate(&[(&s[0..3], m0)]);
        assert!(
            bls_normal_verify_preaggregated_multi_message(&[(&k[0..2], m0), (&k[2..3], m0)], &one)
                .is_err()
        );
        let twice = [k[0], k[0]];
        let doubled = multi_message_aggregate(&[(&[s[0], s[0]], m0)]);
        assert!(bls_normal_verify_preaggregated_multi_message(&[(&twice, m0)], &doubled).is_err());
        // Empty, all-zero and truncated signatures.
        for signature in [&[][..], &[0_u8; 96][..], &agg[..95]] {
            assert!(
                bls_normal_verify_preaggregated_multi_message(
                    &[(&k[0..2], m0), (&k[2..3], m1)],
                    signature
                )
                .is_err()
            );
        }
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_normal_pop_verified_key_requires_a_valid_pop() {
        let (pk, sk) = checked_seed_keypair(&[0x51; 32], Algorithm::BlsNormal).into_parts();
        let (other_public_key, other_secret) =
            checked_seed_keypair(&[0x52; 32], Algorithm::BlsNormal).into_parts();
        let pop = bls_normal_pop_prove(&sk).expect("pop");
        let key = BlsNormalPopVerifiedKey::new(&pk, &pop).expect("valid pop");
        assert_eq!(key.public_key(), &pk);
        assert_eq!(key.payload(), pk.to_bytes().1);
        assert_eq!(key.payload().len(), 48);
        assert_eq!(key.clone(), key);
        assert!(format!("{key:?}").starts_with("BlsNormalPopVerifiedKey"));
        let other_pop = bls_normal_pop_prove(&other_secret).expect("pop");
        assert!(BlsNormalPopVerifiedKey::new(&pk, &other_pop).is_err());
        assert!(BlsNormalPopVerifiedKey::new(&other_public_key, &pop).is_err());
        assert!(BlsNormalPopVerifiedKey::new(&pk, &[]).is_err());
        let (ed, _) = checked_seed_keypair(&[0x53; 32], Algorithm::Ed25519).into_parts();
        assert!(BlsNormalPopVerifiedKey::new(&ed, &pop).is_err());
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_small_aggregate_fast_accepts_valid_and_rejects_bad() {
        let msg = b"bls-small-fast";
        let kp1 = checked_seed_keypair(&[3; 32], Algorithm::BlsSmall);
        let kp2 = checked_seed_keypair(&[4; 32], Algorithm::BlsSmall);
        let (pk1, sk1) = kp1.into_parts();
        let (pk2, sk2) = kp2.into_parts();
        let sig1 = checked_signature(&sk1, msg);
        let sig2 = checked_signature(&sk2, msg);
        let signatures: Vec<&[u8]> = vec![sig1.payload(), sig2.payload()];
        let public_keys: Vec<&PublicKey> = vec![&pk1, &pk2];
        let pops = [
            bls_small_pop_prove(&sk1).expect("pop"),
            bls_small_pop_prove(&sk2).expect("pop"),
        ];
        let pop_refs: Vec<&[u8]> = pops.iter().map(Vec::as_slice).collect();
        bls_small_verify_aggregate_same_message_fast(msg, &signatures, &public_keys, &pop_refs)
            .expect("aggregate fast ok");
        let mut bad_sig = sig2.payload().to_vec();
        bad_sig[0] ^= 0x01;
        let bad_signatures: Vec<&[u8]> = vec![sig1.payload(), bad_sig.as_slice()];
        assert!(
            bls_small_verify_aggregate_same_message_fast(
                msg,
                &bad_signatures,
                &public_keys,
                &pop_refs,
            )
            .is_err(),
            "bad signature must be rejected"
        );
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_small_same_message_wrappers_reject_duplicate_public_keys() {
        let msg = b"bls-small-duplicate-public-key";
        let key_pair = checked_seed_keypair(&[10; 32], Algorithm::BlsSmall);
        let (public_key, private_key) = key_pair.into_parts();
        let signature = checked_signature(&private_key, msg);
        let signatures: Vec<&[u8]> = vec![signature.payload(), signature.payload()];
        let public_keys: Vec<&PublicKey> = vec![&public_key, &public_key];
        let pop = bls_small_pop_prove(&private_key).expect("pop");
        let pops: Vec<&[u8]> = vec![pop.as_slice(), pop.as_slice()];
        assert!(
            bls_small_verify_aggregate_same_message(msg, &signatures, &public_keys, &pops).is_err(),
            "duplicate signer keys must be rejected in fallback wrapper"
        );
        assert!(
            bls_small_verify_aggregate_same_message_fast(msg, &signatures, &public_keys, &pops)
                .is_err(),
            "duplicate signer keys must be rejected in fast wrapper"
        );
    }
    #[cfg(feature = "bls")]
    #[test]
    fn bls_small_same_message_rejects_canceling_key_aggregate_with_valid_pops() {
        use w3f_bls::SerializableToBytes as _;
        let secret = w3f_bls::SecretKeyVT::<w3f_bls::TinyBLS381>::from_seed(
            b"iroha:test:canceling-bls-small",
        );
        let opposite = w3f_bls::SecretKeyVT::<w3f_bls::TinyBLS381>(-secret.0);
        let sk1 =
            PrivateKey::from_bytes(Algorithm::BlsSmall, &secret.to_bytes()).expect("secret key");
        let sk2 = PrivateKey::from_bytes(Algorithm::BlsSmall, &opposite.to_bytes())
            .expect("opposite secret key");
        let pk1 = PublicKey::from(sk1.clone());
        let pk2 = PublicKey::from(sk2.clone());
        let pop1 = bls_small_pop_prove(&sk1).expect("pop 1");
        let pop2 = bls_small_pop_prove(&sk2).expect("pop 2");
        bls_small_pop_verify(&pk1, &pop1).expect("pop 1 verifies");
        bls_small_pop_verify(&pk2, &pop2).expect("pop 2 verifies");
        let msg = b"canceling-wrapper-small";
        let sig1 = checked_signature(&sk1, msg);
        let sig2 = checked_signature(&sk2, msg);
        sig1.verify(&pk1, msg).expect("signature 1 verifies");
        sig2.verify(&pk2, msg).expect("signature 2 verifies");
        let signatures: Vec<&[u8]> = vec![sig1.payload(), sig2.payload()];
        let public_keys: Vec<&PublicKey> = vec![&pk1, &pk2];
        let pop_refs: Vec<&[u8]> = vec![pop1.as_slice(), pop2.as_slice()];
        assert!(
            bls_small_verify_aggregate_same_message_fast(msg, &signatures, &public_keys, &pop_refs)
                .is_err(),
            "fast aggregate wrapper must reject identity aggregate"
        );
        assert!(
            bls_small_verify_aggregate_same_message(msg, &signatures, &public_keys, &pop_refs)
                .is_err(),
            "fallback wrapper must not bypass identity aggregate rejection"
        );
    }
    #[test]
    fn no_such_algorithm_error_displays_identifier() {
        let missing = "rot13-ed25519";
        let err = Error::NoSuchAlgorithm(missing.to_string());
        let rendered = err.to_string();
        assert!(
            rendered.contains(missing),
            "Error Display output `{rendered}` should mention `{missing}`"
        );
        assert!(
            rendered.starts_with("Algorithm"),
            "Display output should remain human readable"
        );
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_secret_key_clone_shares_inner_arc() {
        use crate::mldsa_seed::mldsa65 as seeded;
        use pqcrypto_traits::sign::SecretKey as _;
        let (public, private) =
            seeded::keypair_from_seed(b"iroha:ml-dsa:strong-count").expect("seeded ML-DSA keypair");
        let raw_secret = pqcrypto_mldsa::mldsa65::SecretKey::from_bytes(&private.to_bytes().1)
            .expect("valid ML-DSA secret bytes");
        let key = MlDsaSecretKey::new(&raw_secret);
        assert_eq!(key.strong_count(), 1, "initial strong count must be 1");
        let cloned = key.clone();
        assert_eq!(key.strong_count(), 2, "cloning increments strong count");
        let message = b"iroha:ml-dsa:test-arc-sharing";
        let sig_original = key.try_sign(message).expect("original ML-DSA signature");
        let sig_clone = cloned.try_sign(message).expect("clone ML-DSA signature");
        Signature::from_bytes(&sig_original)
            .verify(&public, message)
            .expect("original ML-DSA signature should verify");
        Signature::from_bytes(&sig_clone)
            .verify(&public, message)
            .expect("clone ML-DSA signature should verify");
        drop(cloned);
        assert_eq!(key.strong_count(), 1, "dropping clone decrements count");
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_secret_key_zeroizer_overwrites_the_full_backend_payload() {
        use pqcrypto_traits::sign::SecretKey as _;

        let (_, private) =
            mldsa_seed::mldsa65::keypair_from_seed(b"iroha:ml-dsa:volatile-secret-zeroization")
                .expect("seeded ML-DSA keypair");
        let mut raw_secret = pqcrypto_mldsa::mldsa65::SecretKey::from_bytes(&private.to_bytes().1)
            .expect("valid ML-DSA secret bytes");
        assert!(raw_secret.as_bytes().iter().any(|byte| *byte != 0));

        zeroize_mldsa_secret_key(&mut raw_secret);

        assert!(raw_secret.as_bytes().iter().all(|byte| *byte == 0));
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_try_sign_with_rng_reports_rng_failure() {
        let (_, key) = seeded_ml_dsa_secret(b"iroha:ml-dsa:signing-rng-failure");
        let mut rng = FailingTryRng;
        let err = key
            .try_sign_with_rng(b"iroha:ml-dsa:message", &mut rng)
            .expect_err("ML-DSA signing RNG failure must fail closed");
        assert!(
            matches!(err, Error::Signing(ref message) if message.contains("hedged RNG seed draw failed")),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_try_sign_with_rng_rejects_all_zero_seed_material() {
        let (_, key) = seeded_ml_dsa_secret(b"iroha:ml-dsa:signing-all-zero");
        let mut rng = FixedTryRng { byte: 0 };
        let err = key
            .try_sign_with_rng(b"iroha:ml-dsa:message", &mut rng)
            .expect_err("all-zero ML-DSA signing seed material must fail closed");
        assert!(
            matches!(err, Error::Signing(ref message) if message.contains("all-zero material")),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_try_sign_with_rng_accepts_nonzero_seed_material() {
        let (public, key) = seeded_ml_dsa_secret(b"iroha:ml-dsa:signing-nonzero");
        let mut rng = FixedTryRng { byte: 0x42 };
        let message = b"iroha:ml-dsa:signing-nonzero-message";
        let signature = key
            .try_sign_with_rng(message, &mut rng)
            .expect("nonzero ML-DSA signing seed material should sign");
        Signature::from_bytes(&signature)
            .verify(&public, message)
            .expect("ML-DSA signature should verify");
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_private_key_from_bytes_signs_after_local_scrub() {
        use crate::mldsa_seed::mldsa65 as seeded;
        let (public, private) = seeded::keypair_from_seed(b"iroha:ml-dsa:from-bytes-scrub")
            .expect("seeded ML-DSA keypair");
        let private_bytes = Zeroizing::new(private.to_bytes().1);
        let parsed = PrivateKey::from_bytes(Algorithm::MlDsa, private_bytes.as_slice())
            .expect("parse ML-DSA private key");
        let message = b"iroha:ml-dsa:parsed-private-key-signs";
        let signature = checked_signature(&parsed, message);
        signature
            .verify(&public, message)
            .expect("parsed ML-DSA private key signs");
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_private_key_parse_rejects_all_zero_material() {
        let all_zero = vec![0u8; pqcrypto_mldsa::mldsa65::secret_key_bytes()];
        let err = PrivateKey::from_bytes(Algorithm::MlDsa, &all_zero)
            .expect_err("all-zero ML-DSA private key material must fail closed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("all-zero material") || rendered.contains("all zero"),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_private_key_parse_uses_strict_secret_validator_for_component_drift() {
        use crate::mldsa_seed::mldsa65 as seeded;
        let (_, private) = seeded::keypair_from_seed(b"iroha:ml-dsa:strict-secret-parse")
            .expect("seeded ML-DSA keypair");
        let mut private_bytes = private.to_bytes().1;
        let last = private_bytes
            .last_mut()
            .expect("ML-DSA secret key has at least one byte");
        *last ^= 0x01;
        let err = PrivateKey::from_bytes(Algorithm::MlDsa, &private_bytes)
            .expect_err("strict ML-DSA secret-key validation must reject component drift");
        assert!(
            err.to_string().contains("internally inconsistent"),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_public_key_parse_rejects_invalid_length() {
        let key_pair =
            checked_seed_keypair(b"iroha:test:mldsa:public-key-length", Algorithm::MlDsa);
        let (_, public_payload) = key_pair.public_key().to_bytes();
        let parsed = PublicKey::from_bytes(Algorithm::MlDsa, public_payload);
        assert!(parsed.is_ok(), "expected valid ML-DSA public key bytes");
        let mut bad = public_payload.to_vec();
        bad.push(0x00);
        let err = PublicKey::from_bytes(Algorithm::MlDsa, &bad).unwrap_err();
        assert!(
            err.0.contains("invalid ML-DSA public key length"),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_public_key_parse_rejects_all_zero_material() {
        let all_zero = vec![0u8; pqcrypto_mldsa::mldsa65::public_key_bytes()];
        let err = PublicKey::from_bytes(Algorithm::MlDsa, &all_zero)
            .expect_err("all-zero ML-DSA public key material must fail closed");
        assert!(
            err.to_string().contains("all-zero material"),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn pqc_verify_aggregate_rejects_empty_input() {
        let empty: [&[u8]; 0] = [];
        let err = pqc_verify_aggregate(&empty, &empty, &empty)
            .expect_err("empty ML-DSA aggregate verification must fail closed");
        assert_eq!(err, Error::BadSignature);
    }
    #[test]
    #[cfg(feature = "rand")]
    fn key_pair_serialize_deserialize_consistent() {
        struct ExposedKeyPair {
            public_key: PublicKey,
            private_key: ExposedPrivateKey,
        }
        impl norito::json::JsonSerialize for ExposedKeyPair {
            fn json_serialize(&self, out: &mut String) {
                use norito::json::{self, Map, Value};
                let mut map = Map::new();
                map.insert(
                    "public_key".into(),
                    json::to_value(&self.public_key).expect("serialize public key"),
                );
                map.insert(
                    "private_key".into(),
                    json::to_value(&self.private_key).expect("serialize private key"),
                );
                norito::json::JsonSerialize::json_serialize(&Value::Object(map), out);
            }
        }
        for algorithm in supported_algorithms() {
            let key_pair = checked_random_keypair(algorithm);
            let exposed_key_pair = ExposedKeyPair {
                public_key: key_pair.public_key.clone(),
                private_key: ExposedPrivateKey(key_pair.private_key.clone()),
            };
            let ser = norito::json::to_json(&exposed_key_pair)
                .unwrap_or_else(|_| panic!("Failed to serialize key pair {:?}", &key_pair));
            let de: KeyPair = norito::json::from_str(&ser)
                .unwrap_or_else(|_| panic!("Failed to deserialize key pair {:?}", &key_pair));
            assert_eq!(key_pair, de);
        }
    }
    #[test]
    #[cfg(feature = "bls")]
    fn bls_pop_hashes_match_reference_contiguous_layout() {
        let pk_bytes = [0x42; 96];
        let pop = [0xA5; 48];
        let mut reference_message = Vec::with_capacity(POP_DST.len() + pk_bytes.len());
        reference_message.extend_from_slice(POP_DST.as_bytes());
        reference_message.extend_from_slice(&pk_bytes);
        let expected_message_hash: [u8; Hash::LENGTH] = Hash::new(&reference_message).into();
        assert_eq!(bls_pop_message_hash(&pk_bytes), expected_message_hash);
        let mut reference_cache_key = Vec::with_capacity(pk_bytes.len() + pop.len());
        reference_cache_key.extend_from_slice(&pk_bytes);
        reference_cache_key.extend_from_slice(&pop);
        assert_eq!(
            bls_pop_cache_key(&pk_bytes, &pop),
            Hash::new(&reference_cache_key)
        );
    }
    #[test]
    #[cfg(feature = "bls")]
    fn bls_pop_cache_is_exact_and_adversarially_bounded() {
        fn material(index: usize) -> (Vec<u8>, Vec<u8>) {
            let index = u64::try_from(index).expect("test index fits u64");
            let mut public_key = vec![0x42; 48];
            public_key[..8].copy_from_slice(&index.to_le_bytes());
            let mut proof = vec![0xA5; 96];
            proof[..8].copy_from_slice(&index.rotate_left(17).to_le_bytes());
            (public_key, proof)
        }
        let mut cache = BlsPopCache::default();
        let overflow = 257;
        for index in 0..BLS_POP_CACHE_CAPACITY + overflow {
            let (public_key, proof) = material(index);
            cache.remember(Algorithm::BlsNormal, &public_key, &proof);
        }
        assert_eq!(cache.len(), BLS_POP_CACHE_CAPACITY);
        assert_eq!(cache.insertion_order.len(), BLS_POP_CACHE_CAPACITY);
        for index in 0..overflow {
            let (public_key, proof) = material(index);
            assert!(
                !cache.contains(Algorithm::BlsNormal, &public_key, &proof),
                "oldest entry {index} must be evicted"
            );
        }
        let (oldest_retained_key, oldest_retained_proof) = material(overflow);
        assert!(cache.contains(
            Algorithm::BlsNormal,
            &oldest_retained_key,
            &oldest_retained_proof
        ));
        let (newest_key, newest_proof) = material(BLS_POP_CACHE_CAPACITY + overflow - 1);
        assert!(cache.contains(Algorithm::BlsNormal, &newest_key, &newest_proof));
        let mut substituted_proof = newest_proof.clone();
        substituted_proof[0] ^= 1;
        assert!(!cache.contains(Algorithm::BlsNormal, &newest_key, &substituted_proof));
        assert!(!cache.contains(Algorithm::BlsSmall, &newest_key, &newest_proof));
        // A digest is only an index: even an adversarially populated collision
        // bucket cannot make different exact material appear cached.
        let collision_digest =
            bls_pop_cache_digest(Algorithm::BlsNormal, &newest_key, &substituted_proof);
        let mut collision_cache = BlsPopCache::default();
        collision_cache
            .entries
            .entry(collision_digest)
            .or_default()
            .push(Arc::new(BlsPopCacheKey {
                algorithm: Algorithm::BlsNormal,
                public_key: newest_key.clone(),
                proof: newest_proof.clone(),
            }));
        assert!(!collision_cache.contains_at_digest(
            collision_digest,
            Algorithm::BlsNormal,
            &newest_key,
            &substituted_proof,
        ));
        cache.remember(Algorithm::BlsNormal, &newest_key, &newest_proof);
        assert_eq!(
            cache.len(),
            BLS_POP_CACHE_CAPACITY,
            "an exact duplicate must not consume capacity"
        );
    }
    #[test]
    #[cfg(feature = "bls")]
    fn bls_pop_prove_and_verify_roundtrip() {
        // Generate a BLS-normal key pair
        let kp = checked_seed_keypair(
            b"iroha:test:bls_pop_prove_and_verify_roundtrip:1",
            Algorithm::BlsNormal,
        );
        // Prove possession
        let pop = bls_normal_pop_prove(kp.private_key()).expect("pop prove");
        // Verify
        bls_normal_pop_verify(kp.public_key(), &pop).expect("pop verify");
        // Negative: wrong key should fail
        let other = checked_seed_keypair(
            b"iroha:test:bls_pop_prove_and_verify_roundtrip:2",
            Algorithm::BlsNormal,
        );
        assert!(bls_normal_pop_verify(other.public_key(), &pop).is_err());
    }
    #[test]
    #[cfg(feature = "bls")]
    fn bls_pop_rejects_unhashed_message() {
        use crate::secrecy::ExposeSecret;
        // PoP signed over POP_DST || pk (unhashed) must be rejected.
        let kp = checked_seed_keypair(
            b"iroha:test:bls_pop_rejects_unhashed_message:1",
            Algorithm::BlsNormal,
        );
        let (algorithm, pk_bytes) = kp
            .public_key()
            .try_to_bytes()
            .expect("fixture BLS public key must be well-formed");
        assert_eq!(algorithm, Algorithm::BlsNormal);
        let mut unhashed_msg = Vec::with_capacity(POP_DST.len() + pk_bytes.len());
        unhashed_msg.extend_from_slice(POP_DST.as_bytes());
        unhashed_msg.extend_from_slice(pk_bytes);
        let pop = signature::bls::BlsNormal::try_sign(
            &unhashed_msg,
            match kp.private_key().0.expose_secret() {
                PrivateKeyInner::BlsNormal(sk) => sk,
                _ => unreachable!(),
            },
        )
        .expect("BLS sign");
        assert!(bls_normal_pop_verify(kp.public_key(), &pop).is_err());
    }
    #[test]
    #[cfg(feature = "bls")]
    fn bls_small_pop_roundtrip() {
        let kp = checked_seed_keypair(b"iroha:test:bls_small_pop_roundtrip:1", Algorithm::BlsSmall);
        let pop = bls_small_pop_prove(kp.private_key()).expect("small pop prove");
        bls_small_pop_verify(kp.public_key(), &pop).expect("small pop verify");
        let other =
            checked_seed_keypair(b"iroha:test:bls_small_pop_roundtrip:2", Algorithm::BlsSmall);
        assert!(bls_small_pop_verify(other.public_key(), &pop).is_err());
    }
    #[test]
    #[cfg(feature = "bls")]
    fn bls_pop_paths_reject_malformed_public_key_without_panic() {
        let malformed_normal = PublicKey(PublicKeyCompact::new(Algorithm::BlsNormal, &[]));
        let err = bls_normal_pop_verify(&malformed_normal, &[])
            .expect_err("malformed normal BLS key must fail closed");
        assert!(matches!(err, Error::Parse(_)));
        let public_keys = vec![&malformed_normal];
        let signatures: Vec<&[u8]> = vec![&[]];
        let pops: Vec<&[u8]> = vec![&[]];
        let err = bls_normal_verify_aggregate_same_message(
            b"malformed-bls-pop-aggregate",
            &signatures,
            &public_keys,
            &pops,
        )
        .expect_err("malformed aggregate key must fail during PoP collection");
        assert!(matches!(err, Error::Parse(_)));
        let malformed_small = PublicKey(PublicKeyCompact::new(Algorithm::BlsSmall, &[]));
        let err = bls_small_pop_verify(&malformed_small, &[])
            .expect_err("malformed small BLS key must fail closed");
        assert!(matches!(err, Error::Parse(_)));
    }
    #[test]
    fn private_key_format_or_serialize_redacted() {
        let key_pair = checked_seed_keypair(
            b"iroha:test:private_key_format_or_serialize_redacted:1",
            Algorithm::default(),
        );
        let (_, private_key) = key_pair.into_parts();
        assert_eq!(
            norito::json::to_json(&private_key).expect("Couldn't serialize key"),
            format!("\"{PRIVATE_KEY_REDACTED}\"")
        );
        assert_eq!(format!("{}", &private_key), PRIVATE_KEY_REDACTED);
    }
    #[test]
    fn encode_decode_algorithm_consistent() {
        for algorithm in supported_algorithms() {
            let encoded_algorithm = algorithm.encode();
            let decoded_algorithm =
                Algorithm::decode(&mut encoded_algorithm.as_slice()).expect("Failed to decode");
            assert_eq!(
                algorithm, decoded_algorithm,
                "Failed to decode encoded {:?}",
                &algorithm
            );
        }
    }
    #[test]
    fn key_pair_match() {
        KeyPair::new(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
                .parse()
                .expect("Public key not in mulithash format"),
            "80262093CA389FC2979F3F7D2A7F8B76C70DE6D5EAF5FA58D4F93CB8B0FB298D398ACC"
                .parse()
                .expect("Private key not in mulithash format"),
        )
        .unwrap();
        #[cfg(feature = "bls")]
        {
            KeyPair::new("ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
                .parse()
                .expect("Public key not in mulithash format"),
                "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F"
                .parse()
                .expect("Private key not in mulithash format")
            ).unwrap();
        }
        #[cfg(feature = "gost")]
        {
            for algorithm in [
                Algorithm::Gost3410_2012_256ParamSetA,
                Algorithm::Gost3410_2012_256ParamSetB,
                Algorithm::Gost3410_2012_256ParamSetC,
                Algorithm::Gost3410_2012_512ParamSetA,
                Algorithm::Gost3410_2012_512ParamSetB,
            ] {
                let key_pair = checked_seed_keypair(b"iroha:test:key_pair_match:1", algorithm);
                let public: PublicKey = key_pair
                    .public_key()
                    .to_string()
                    .parse()
                    .expect("public multihash should parse");
                let private: PrivateKey = ExposedPrivateKey(key_pair.private_key().clone())
                    .to_string()
                    .parse()
                    .expect("private multihash should parse");
                KeyPair::new(public, private).expect("GOST multihash roundtrip");
            }
        }
    }
    #[test]
    #[cfg(all(feature = "bls", feature = "rand"))]
    fn bls_normal_multi_message_duplicates_are_rejected() {
        let (pk1, sk1) = signature::bls::BlsNormal::try_keypair(super::KeyGenOption::Random)
            .expect("BLS keypair");
        let (pk2, sk2) = signature::bls::BlsNormal::try_keypair(super::KeyGenOption::Random)
            .expect("BLS keypair");
        let message = b"duplicate-multi-msg".to_vec();
        let sig1 = signature::bls::BlsNormal::try_sign(&message, &sk1).expect("BLS sign");
        let sig2 = signature::bls::BlsNormal::try_sign(&message, &sk2).expect("BLS sign");
        let pk1_bytes = pk1.to_bytes();
        let pk2_bytes = pk2.to_bytes();
        let msgs: Vec<&[u8]> = vec![message.as_slice(), message.as_slice()];
        let signature_refs: Vec<&[u8]> = vec![sig1.as_slice(), sig2.as_slice()];
        let pk_refs: Vec<&[u8]> = vec![pk1_bytes.as_slice(), pk2_bytes.as_slice()];
        super::signature::bls::verify_aggregate_multi_message_normal(
            &msgs,
            &signature_refs,
            &pk_refs,
        )
        .expect_err("aggregate verifier must reject duplicate messages");
        super::bls_normal_verify_aggregate_multi_message(&msgs, &signature_refs, &pk_refs)
            .expect_err("wrapper must reject duplicate messages");
    }
    #[test]
    #[cfg(all(feature = "bls", feature = "rand"))]
    fn bls_small_multi_message_duplicates_are_rejected() {
        let (pk1, sk1) = signature::bls::BlsSmall::try_keypair(super::KeyGenOption::Random)
            .expect("BLS keypair");
        let (pk2, sk2) = signature::bls::BlsSmall::try_keypair(super::KeyGenOption::Random)
            .expect("BLS keypair");
        let message = b"duplicate-multi-msg-small".to_vec();
        let sig1 = signature::bls::BlsSmall::try_sign(&message, &sk1).expect("BLS sign");
        let sig2 = signature::bls::BlsSmall::try_sign(&message, &sk2).expect("BLS sign");
        let pk1_bytes = pk1.to_bytes();
        let pk2_bytes = pk2.to_bytes();
        let msgs: Vec<&[u8]> = vec![message.as_slice(), message.as_slice()];
        let signature_refs: Vec<&[u8]> = vec![sig1.as_slice(), sig2.as_slice()];
        let pk_refs: Vec<&[u8]> = vec![pk1_bytes.as_slice(), pk2_bytes.as_slice()];
        super::signature::bls::verify_aggregate_multi_message_small(
            &msgs,
            &signature_refs,
            &pk_refs,
        )
        .expect_err("aggregate verifier must reject duplicate messages");
        super::bls_small_verify_aggregate_multi_message(&msgs, &signature_refs, &pk_refs)
            .expect_err("wrapper must reject duplicate messages");
    }
    #[test]
    #[cfg(feature = "rand")]
    fn encode_decode_public_key_consistent() {
        for algorithm in supported_algorithms() {
            let key_pair = checked_random_keypair(algorithm);
            let (public_key, _) = key_pair.into_parts();
            let encoded_public_key = public_key.encode();
            let decoded_public_key =
                PublicKey::decode(&mut encoded_public_key.as_slice()).expect("Failed to decode");
            assert_eq!(
                public_key, decoded_public_key,
                "Failed to decode encoded Public Key{:?}",
                &public_key
            );
        }
    }
    #[test]
    fn public_key_norito_roundtrip() {
        let pk: PublicKey =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
                .parse()
                .expect("public key");
        let mut buf = Vec::new();
        norito::core::serialize_to_buffer(&pk, &mut buf).expect("serialize public key");
        let (decoded, used) = <PublicKey as norito::core::DecodeFromSlice>::decode_from_slice(&buf)
            .expect("decode public key slice");
        assert_eq!(used, buf.len());
        assert_eq!(decoded, pk);
        let codec_bytes = pk.encode();
        let mut cursor = codec_bytes.as_slice();
        let codec_decoded =
            <PublicKey as Decode>::decode(&mut cursor).expect("codec decode public key");
        assert_eq!(codec_decoded, pk);
    }
    #[test]
    fn public_key_payload_ceiling_covers_feature_independent_algorithms() {
        assert_eq!(MAX_PUBLIC_KEY_PAYLOAD_BYTES, 8_258);
        const {
            assert!(MAX_PUBLIC_KEY_PAYLOAD_BYTES >= ML_DSA_65_PUBLIC_KEY_BYTES);
        }
    }

    #[cfg(feature = "sm")]
    #[test]
    fn maximum_accepted_sm2_public_key_payload_matches_protocol_ceiling() {
        let distid = "x".repeat(u16::MAX as usize / 8);
        let private = Sm2PrivateKey::from_seed(&distid, b"maximum-distid-payload")
            .expect("maximum SM2 distinguishing identifier is accepted");
        let payload =
            sm::encode_sm2_public_key_payload(&distid, &private.public_key().to_sec1_bytes(false))
                .expect("encode maximum canonical SM2 public key payload");
        assert_eq!(payload.len(), MAX_PUBLIC_KEY_PAYLOAD_BYTES);
        let key = PublicKey::from_bytes(Algorithm::Sm2, &payload)
            .expect("maximum-size canonical SM2 public key remains decodable");
        let literal = key
            .try_to_multihash_string()
            .expect("maximum-size canonical multihash");
        assert_eq!(literal.len(), 2 * (2 + 2 + MAX_PUBLIC_KEY_PAYLOAD_BYTES));
        assert_bounded_public_key_json(&literal, &key);
    }
    #[cfg(feature = "sm")]
    #[test]
    fn sm2_public_key_multihash_and_prefixed_roundtrip() {
        let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, [0x42; 32])
            .expect("construct SM2 private key");
        let sm2_pk = private.public_key();
        let sec1 = sm2_pk.to_sec1_bytes(false);
        let payload = sm::encode_sm2_public_key_payload(sm2_pk.distid(), &sec1).expect("payload");
        let pk = PublicKey::from_bytes(Algorithm::Sm2, &payload).expect("construct SM2 key");
        let canonical = pk
            .try_to_multihash_string()
            .expect("checked SM2 multihash formatting");
        let payload_hex = hex::encode_upper(&payload);
        assert!(
            canonical.starts_with("8626"),
            "SM2 multihash should start with algorithm prefix"
        );
        assert!(
            canonical.ends_with(&payload_hex),
            "SM2 multihash should embed payload bytes"
        );
        let prefixed = pk
            .try_to_prefixed_string()
            .expect("checked SM2 prefixed formatting");
        assert_eq!(prefixed, format!("sm2:{canonical}"));
        let parsed_prefixed: PublicKey = prefixed.parse().expect("parse prefixed key");
        assert_eq!(parsed_prefixed, pk);
        let parsed: PublicKey = canonical.parse().expect("parse bare multihash");
        assert_eq!(parsed, pk);
    }
    #[cfg(feature = "sm")]
    #[test]
    fn sm2_private_key_checked_payload_and_prefixed_roundtrip() {
        let (_, private_key) = KeyPair::try_from_seed(vec![0x54; 32], Algorithm::Sm2)
            .expect("checked SM2 seeded keypair")
            .into_parts();
        let (algorithm, payload) = private_key
            .try_to_bytes()
            .expect("checked SM2 private payload extraction");
        let exposed = ExposedPrivateKey(private_key.clone());
        assert_eq!(algorithm, Algorithm::Sm2);
        assert!(!payload.is_empty(), "SM2 private payload must not be empty");
        assert_eq!(private_key.to_bytes(), (algorithm, payload.clone()));
        assert_eq!(
            PrivateKey::from_bytes(algorithm, &payload).expect("decode checked SM2 payload"),
            private_key
        );
        let canonical = exposed
            .try_to_multihash_string()
            .expect("checked SM2 private multihash formatting");
        let prefixed = exposed
            .try_to_prefixed_string()
            .expect("checked SM2 private prefixed formatting");
        assert_eq!(prefixed, format!("sm2:{canonical}"));
        let parsed_prefixed: ExposedPrivateKey = prefixed.parse().expect("parse prefixed key");
        assert_eq!(parsed_prefixed, exposed);
    }
    #[test]
    fn exposed_private_key_explicit_exports_roundtrip_and_debug_is_redacted() {
        let (_, private_key) = KeyPair::try_from_seed(vec![0x55; 32], Algorithm::Ed25519)
            .expect("checked Ed25519 seeded keypair")
            .into_parts();
        let (algorithm, payload) = private_key
            .try_to_bytes()
            .expect("checked private payload extraction");
        let payload_hex = hex::encode_upper(payload);
        let exposed = ExposedPrivateKey(private_key);
        let canonical = exposed
            .try_to_multihash_string()
            .expect("checked private multihash formatting");
        let prefixed = exposed
            .try_to_prefixed_string()
            .expect("checked private prefixed formatting");
        assert_eq!(exposed.to_string(), canonical);
        assert_eq!(exposed.to_prefixed_string(), prefixed);
        assert_eq!(
            norito::json::to_json(&exposed).expect("serialize explicitly exposed private key"),
            format!("\"{canonical}\"")
        );
        assert_eq!(
            canonical
                .parse::<ExposedPrivateKey>()
                .expect("parse bare private-key multihash"),
            exposed
        );
        assert_eq!(
            prefixed
                .parse::<ExposedPrivateKey>()
                .expect("parse prefixed private-key multihash"),
            exposed
        );
        let debug = format!("{exposed:?}");
        assert!(debug.contains("ExposedPrivateKey"));
        assert!(debug.contains(&format!("{algorithm:?}")));
        assert!(debug.contains(PRIVATE_KEY_REDACTED));
        assert!(!debug.contains(&canonical));
        assert!(!debug.contains(&prefixed));
        assert!(!debug.contains(&payload_hex));
    }
    #[test]
    fn public_key_compact_roundtrip_via_canonical_decode() {
        let pk: PublicKey =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
                .parse()
                .expect("public key");
        let compact = pk.0.clone();
        let mut payload = Vec::new();
        norito::core::serialize_to_buffer(&compact, &mut payload).expect("serialize compact");
        let (decoded, used) = norito::core::decode_field_canonical::<PublicKeyCompact>(&payload)
            .expect("decode compact");
        assert!(used <= payload.len());
        let from_decoded = PublicKey(decoded.clone());
        let from_original = PublicKey(compact.clone());
        assert_eq!(from_decoded, from_original);
    }
    #[test]
    fn public_key_encoded_len_exact_matches_norito() {
        let pk: PublicKey =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
                .parse()
                .expect("public key");
        let expected = norito::core::to_bytes(&pk)
            .expect("encode public key")
            .len()
            - norito::core::Header::SIZE;
        assert_eq!(
            norito::core::SerializePayload::encoded_len_exact(&pk)
                .expect("exact public key length"),
            expected
        );
    }
    #[test]
    #[cfg(feature = "pqc")]
    fn mldsa_decode_and_structural_encoders_avoid_full_key_reparse() {
        let public_key = checked_seed_keypair(&[0x5A; 32], Algorithm::MlDsa)
            .public_key()
            .clone();
        let compact = &public_key.0;
        let expected_hint = <ConstVec<u8> as norito::core::SerializePayload>::encoded_len_hint(
            &compact.algorithm_and_payload,
        );
        let expected_exact = <ConstVec<u8> as norito::core::SerializePayload>::encoded_len_exact(
            &compact.algorithm_and_payload,
        );
        reset_public_key_validation_call_count();
        let (algorithm, payload) = public_key
            .try_to_bytes()
            .expect("generated ML-DSA compact state");
        public_key_decode::validate(algorithm, payload).expect("borrowed ML-DSA decode validation");
        assert_eq!(
            norito::core::SerializePayload::encoded_len_hint(compact),
            expected_hint
        );
        assert_eq!(
            norito::core::SerializePayload::encoded_len_exact(compact),
            expected_exact
        );
        assert_eq!(
            norito::core::SerializePayload::encoded_len_hint(&public_key),
            expected_hint
        );
        assert_eq!(
            norito::core::SerializePayload::encoded_len_exact(&public_key),
            expected_exact
        );
        assert_eq!(
            public_key_validation_call_count(),
            0,
            "Norito sizing must not parse ML-DSA key material"
        );

        let mut compact_norito = Vec::new();
        norito::core::serialize_to_buffer(compact, &mut compact_norito)
            .expect("structural compact Norito encoding");
        let mut public_norito = Vec::new();
        norito::core::serialize_to_buffer(&public_key, &mut public_norito)
            .expect("structural public-key Norito encoding");
        assert_eq!(compact_norito, public_norito);
        let (decoded, used) =
            <PublicKey as norito::core::DecodeFromSlice>::decode_from_slice(&public_norito)
                .expect("borrowed ML-DSA Norito decode validation");
        assert_eq!(used, public_norito.len());
        assert_eq!(decoded, public_key);
        let canonical = public_key
            .try_to_multihash_string()
            .expect("structural multihash formatting");
        assert_eq!(public_key.to_string(), canonical);
        assert_eq!(
            public_key
                .try_to_prefixed_string()
                .expect("structural prefixed formatting"),
            format!("ml-dsa:{canonical}")
        );
        assert_bounded_public_key_json(&canonical, &public_key);
        assert_eq!(
            public_key_validation_call_count(),
            0,
            "Norito, checked JSON, and formatting must not reparse ML-DSA key material"
        );
        parse_public_key_material(algorithm, payload)
            .expect("explicit key-material parsing succeeds");
        assert_eq!(
            public_key_validation_call_count(),
            1,
            "test counter must observe explicit key-material parsing"
        );
    }
    #[test]
    fn public_key_compact_try_deserialize_rejects_invalid_payload() {
        let compact = PublicKeyCompact::new(Algorithm::Ed25519, &[]);
        let (payload, flags) =
            norito::codec::encode_with_header_flags(&compact.algorithm_and_payload);
        let framed =
            norito::core::frame_bare_with_header_flags::<PublicKeyCompact>(&payload, flags)
                .expect("frame compact");
        let archived = norito::from_bytes::<PublicKeyCompact>(&framed).expect("archive");
        let err = <PublicKeyCompact as norito::core::DeserializePayload>::try_deserialize(archived)
            .expect_err("invalid compact payload");
        assert!(matches!(
            &err,
            norito::core::Error::InvalidValue {
                context: "public key"
            }
        ));
        assert_eq!(err.to_string(), "invalid public key");
    }
    #[test]
    fn public_key_compact_decode_from_slice_rejects_invalid_payload() {
        let compact = PublicKeyCompact::new(Algorithm::Ed25519, &[]);
        let mut payload = Vec::new();
        norito::core::serialize_to_buffer(&compact.algorithm_and_payload, &mut payload)
            .expect("serialize raw compact bytes");
        let err = <PublicKeyCompact as norito::core::DecodeFromSlice>::decode_from_slice(&payload)
            .expect_err("invalid compact payload");
        assert!(matches!(
            &err,
            norito::core::Error::InvalidValue {
                context: "public key"
            }
        ));
        assert_eq!(err.to_string(), "invalid public key");
    }
    #[test]
    fn public_key_compact_serialize_rejects_malformed_envelope() {
        let compact = PublicKeyCompact::new(Algorithm::Ed25519, &[]);
        let mut encoded = Vec::new();
        norito::core::serialize_to_buffer(&compact, &mut encoded)
            .expect_err("malformed compact state must fail serialization");
        assert!(norito::core::SerializePayload::encoded_len_hint(&compact).is_none());
        assert!(norito::core::SerializePayload::encoded_len_exact(&compact).is_none());
    }

    #[test]
    fn public_key_structural_envelope_covers_every_compiled_algorithm() {
        fn accepted(algorithm: Algorithm, payload: Vec<u8>) {
            validate_public_key_structural_envelope(algorithm, &payload)
                .unwrap_or_else(|error| panic!("valid {algorithm:?} envelope failed: {error}"));
            let mut short = payload.clone();
            short.pop();
            assert!(
                validate_public_key_structural_envelope(algorithm, &short).is_err(),
                "short {algorithm:?} envelope was accepted"
            );
            let mut long = payload;
            long.push(1);
            assert!(
                validate_public_key_structural_envelope(algorithm, &long).is_err(),
                "long {algorithm:?} envelope was accepted"
            );
        }

        accepted(Algorithm::Ed25519, vec![1; 32]);
        let mut secp = vec![1; 33];
        secp[0] = 0x02;
        accepted(Algorithm::Secp256k1, secp.clone());
        secp[0] = 0x04;
        assert!(validate_public_key_structural_envelope(Algorithm::Secp256k1, &secp).is_err());
        accepted(Algorithm::MlDsa, vec![1; ML_DSA_65_PUBLIC_KEY_BYTES]);
        #[cfg(feature = "bls")]
        {
            accepted(Algorithm::BlsNormal, vec![1; 48]);
            accepted(Algorithm::BlsSmall, vec![1; 96]);
        }
        #[cfg(feature = "gost")]
        {
            accepted(Algorithm::Gost3410_2012_256ParamSetA, vec![1; 64]);
            accepted(Algorithm::Gost3410_2012_256ParamSetB, vec![1; 64]);
            accepted(Algorithm::Gost3410_2012_256ParamSetC, vec![1; 64]);
            accepted(Algorithm::Gost3410_2012_512ParamSetA, vec![1; 128]);
            accepted(Algorithm::Gost3410_2012_512ParamSetB, vec![1; 128]);
        }
        #[cfg(feature = "sm")]
        {
            let mut sm2 = vec![0, 3];
            sm2.extend_from_slice(b"abc");
            sm2.push(0x04);
            sm2.extend_from_slice(&[1; 64]);
            accepted(Algorithm::Sm2, sm2.clone());

            let mut wrong_length = sm2.clone();
            wrong_length[..2].copy_from_slice(&4_u16.to_be_bytes());
            assert!(
                validate_public_key_structural_envelope(Algorithm::Sm2, &wrong_length).is_err()
            );
            let mut invalid_utf8 = sm2.clone();
            invalid_utf8[2] = 0xff;
            assert!(
                validate_public_key_structural_envelope(Algorithm::Sm2, &invalid_utf8).is_err()
            );
            let mut wrong_sec1_tag = sm2;
            wrong_sec1_tag[5] = 0x02;
            assert!(
                validate_public_key_structural_envelope(Algorithm::Sm2, &wrong_sec1_tag).is_err()
            );
        }
    }
    #[test]
    fn public_key_compact_to_full_rejects_malformed_state_without_panic() {
        let malformed_payload = PublicKeyCompact::new(Algorithm::Ed25519, &[]);
        assert!(PublicKeyMaterial::try_from(&malformed_payload).is_err());
        let missing_tag = PublicKeyCompact {
            algorithm_and_payload: ConstVec::new(Vec::new()),
        };
        assert!(PublicKeyMaterial::try_from(&missing_tag).is_err());
    }
    #[test]
    fn public_key_compact_try_from_full_preserves_checked_payload() {
        let public_key = KeyPair::try_from_seed(vec![0x56; 32], Algorithm::Ed25519)
            .expect("checked Ed25519 seeded keypair")
            .public_key()
            .clone();
        let (algorithm, payload) = public_key
            .try_to_bytes()
            .expect("generated public key must be well-formed");
        let PublicKeyMaterial::Decoded(full) =
            parse_public_key_material(algorithm, payload).expect("full key parses")
        else {
            panic!("expected decoded key material");
        };
        let compact = PublicKeyCompact::from(full);
        assert_eq!(compact.try_algorithm().expect("algorithm tag"), algorithm);
        assert_eq!(compact.try_payload().expect("payload"), payload);
    }
    #[test]
    fn public_key_full_payload_borrows_ed25519_payload() {
        let public_key = checked_seed_keypair(&[0x42; 32], Algorithm::Ed25519)
            .public_key()
            .clone();
        let (algorithm, payload) = public_key
            .try_to_bytes()
            .expect("generated public key must be well-formed");
        let PublicKeyMaterial::Decoded(full) =
            parse_public_key_material(algorithm, payload).expect("full key parses")
        else {
            panic!("expected decoded key material");
        };
        match full.payload() {
            Cow::Borrowed(canonical_payload) => assert_eq!(canonical_payload, payload),
            Cow::Owned(_) => panic!("Ed25519 full public key payload should borrow"),
        }
    }
    #[test]
    #[cfg(feature = "bls")]
    fn public_key_full_payload_borrows_bls_payloads() {
        for algorithm in [Algorithm::BlsNormal, Algorithm::BlsSmall] {
            let public_key = checked_seed_keypair(&[0x42; 32], algorithm)
                .public_key()
                .clone();
            let (algorithm, payload) = public_key
                .try_to_bytes()
                .expect("generated BLS public key must be well-formed");
            let PublicKeyMaterial::Decoded(full) =
                parse_public_key_material(algorithm, payload).expect("full key parses")
            else {
                panic!("expected decoded key material");
            };
            match full.payload() {
                Cow::Borrowed(canonical_payload) => assert_eq!(canonical_payload, payload),
                Cow::Owned(_) => panic!("BLS full public key payload should borrow"),
            }
        }
    }
    #[test]
    fn public_key_norito_golden_archive() {
        let pk: PublicKey =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
                .parse()
                .expect("public key");
        let framed = norito::core::to_bytes(&pk).expect("encode public key");
        let actual_hex = hex::encode(&framed);
        let expected_hex = "4e5254300000b6b01d0a3d2b9cfe06ff97af6ba0f622004a00000000000000ff3888681ae90906022100000000000000010001ed01f601d701b5012c0170013201d0013a01ec0169016f0120016801bd015301100115012801f301c701b60108011b01ff010501a10166012d017f01c20145";
        assert_eq!(
            actual_hex, expected_hex,
            "public key Norito archive changed"
        );
    }
    #[test]
    fn public_key_try_deserialize_rejects_invalid_payload() {
        let bogus = PublicKeyCompact::new(Algorithm::Ed25519, &[]);
        let (payload, flags) =
            norito::codec::encode_with_header_flags(&bogus.algorithm_and_payload);
        let framed = norito::core::frame_bare_with_header_flags::<PublicKey>(&payload, flags)
            .expect("frame");
        let archived = norito::from_bytes::<PublicKey>(&framed).expect("archive");
        let err = <PublicKey as norito::core::DeserializePayload>::try_deserialize(archived)
            .expect_err("invalid key");
        assert!(matches!(
            &err,
            norito::core::Error::InvalidValue {
                context: "public key"
            }
        ));
        assert_eq!(err.to_string(), "invalid public key");
    }
    #[test]
    fn public_key_norito_serialize_rejects_malformed_envelope() {
        let malformed = PublicKey(PublicKeyCompact::new(Algorithm::Ed25519, &[]));
        let mut encoded = Vec::new();
        norito::core::serialize_to_buffer(&malformed, &mut encoded)
            .expect_err("malformed public-key state must fail serialization");
        assert!(norito::core::SerializePayload::encoded_len_hint(&malformed).is_none());
        assert!(norito::core::SerializePayload::encoded_len_exact(&malformed).is_none());
    }
    #[test]
    fn public_key_try_to_bytes_rejects_malformed_compact_state_without_panic() {
        let valid = checked_seed_keypair(&[0x42; 32], Algorithm::Ed25519)
            .public_key()
            .clone();
        let missing_tag = PublicKey(PublicKeyCompact {
            algorithm_and_payload: ConstVec::new(Vec::new()),
        });
        let invalid_tag = PublicKey(PublicKeyCompact {
            algorithm_and_payload: ConstVec::new(vec![0xff]),
        });
        assert_eq!(
            valid.try_algorithm().expect("valid algorithm"),
            Algorithm::Ed25519
        );
        missing_tag
            .try_algorithm()
            .expect_err("missing compact algorithm tag must fail closed");
        missing_tag
            .try_to_bytes()
            .expect_err("missing compact algorithm tag must fail closed");
        invalid_tag
            .try_algorithm()
            .expect_err("invalid compact algorithm tag must fail closed");
    }
    #[test]
    fn public_key_hash_and_ord_handle_malformed_compact_state_without_panic() {
        let valid = checked_seed_keypair(&[0x42; 32], Algorithm::Ed25519)
            .public_key()
            .clone();
        let missing_tag = PublicKey(PublicKeyCompact {
            algorithm_and_payload: ConstVec::new(Vec::new()),
        });
        let invalid_tag = PublicKey(PublicKeyCompact {
            algorithm_and_payload: ConstVec::new(vec![0xff]),
        });
        let mut hashed = std::collections::HashSet::new();
        hashed.insert(valid.clone());
        hashed.insert(missing_tag.clone());
        hashed.insert(invalid_tag.clone());
        assert_eq!(hashed.len(), 3);
        let mut sorted = std::collections::BTreeSet::new();
        sorted.insert(valid.clone());
        sorted.insert(missing_tag.clone());
        sorted.insert(invalid_tag);
        assert_eq!(sorted.len(), 3);
        assert!(
            sorted.iter().next().is_some_and(|key| key == &valid),
            "valid public keys should keep the existing order before malformed fallback keys"
        );
        assert!(valid < missing_tag);
    }
    #[test]
    fn public_key_fallible_string_encoders_reject_malformed_envelopes_without_panic() {
        let missing_tag = PublicKey(PublicKeyCompact {
            algorithm_and_payload: ConstVec::new(Vec::new()),
        });
        missing_tag
            .try_to_multihash_string()
            .expect_err("missing algorithm tag must not format as multihash");
        missing_tag
            .try_to_prefixed_string()
            .expect_err("missing algorithm tag must not format as prefixed multihash");

        let oversized_payload = vec![0_u8; MAX_PUBLIC_KEY_PAYLOAD_BYTES + 1];
        let oversized = PublicKey(PublicKeyCompact::new(
            Algorithm::Ed25519,
            &oversized_payload,
        ));
        oversized
            .try_to_multihash_string()
            .expect_err("above-protocol payload must not format as multihash");
        oversized
            .try_to_prefixed_string()
            .expect_err("above-protocol payload must not format as prefixed multihash");
    }
    #[test]
    fn public_key_infallible_formatters_handle_malformed_compact_state_without_panic() {
        let missing_tag = PublicKey(PublicKeyCompact {
            algorithm_and_payload: ConstVec::new(Vec::new()),
        });
        let malformed_payload = PublicKey(PublicKeyCompact::new(Algorithm::Ed25519, &[]));
        let missing_display = missing_tag.to_string();
        assert_eq!(missing_display, "invalid-public-key:");
        assert!(format!("{missing_tag:?}").contains("missing public key algorithm tag"));
        let payload_display = malformed_payload.to_string();
        assert_eq!(payload_display, "invalid-public-key:00");
        assert!(format!("{malformed_payload:?}").contains("invalid-public-key:00"));
        assert_eq!(
            malformed_payload.to_prefixed_string(),
            "invalid-public-key:00"
        );
        let json = norito::json::to_json(&missing_tag).expect("serialize malformed key marker");
        assert_eq!(json, r#""invalid-public-key:""#);
        norito::json::from_json::<PublicKey>(&json)
            .expect_err("malformed marker must not deserialize as a public key");
        let payload_json = norito::json::to_json(&malformed_payload)
            .expect("malformed payload renders a deterministic marker");
        assert_eq!(payload_json, r#""invalid-public-key:00""#);
        norito::json::from_json::<PublicKey>(&payload_json)
            .expect_err("structurally formatted invalid payload must still fail admission");
    }
    #[test]
    fn keypair_new_rejects_malformed_public_key_without_panic() {
        let (_, private_key) = KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519)
            .expect("seeded keypair")
            .into_parts();
        let malformed = PublicKey(PublicKeyCompact::new(Algorithm::Ed25519, &[]));
        let err = KeyPair::new(malformed, private_key)
            .expect_err("malformed public key must fail closed");
        assert!(matches!(err, Error::Parse(_)));
    }
    #[test]
    #[cfg(feature = "rand")]
    fn public_key_from_bytes_roundtrip() {
        let key_pair = checked_random_keypair(Algorithm::default());
        let (public_key, _) = key_pair.into_parts();
        let (alg, bytes) = public_key
            .try_to_bytes()
            .expect("generated public key must be well-formed");
        let reconstructed = PublicKey::from_bytes(alg, bytes).expect("Should decode");
        assert_eq!(public_key, reconstructed);
    }
    #[test]
    fn confidential_discard_zeroizes_public_key_and_signature_copies() {
        let mut public_key = KeyPair::try_from_seed(vec![0xA7; 32], Algorithm::Ed25519)
            .expect("checked discard fixture")
            .public_key()
            .clone();
        public_key.zeroize_for_confidential_discard();
        assert!(public_key.0.algorithm_and_payload.is_empty());

        let mut signature = Signature::from_bytes(&[0xA8; 64]);
        signature.zeroize();
        assert!(signature.payload().is_empty());
    }
    #[test]
    fn typed_signature_confidential_discard_is_idempotent() {
        let mut signature = SignatureOf::<()>::from_signature(Signature::from_bytes(&[0xA9; 64]));

        signature.zeroize_for_confidential_discard();
        assert!(signature.payload().is_empty());

        signature.zeroize_for_confidential_discard();
        assert!(signature.payload().is_empty());
    }
    #[test]
    fn confidential_discard_helper_zeroizes_supported_shapes_idempotently() {
        let mut selector = true;
        let mut amount = u128::MAX;
        let mut fixed_bytes = [0xA5; 32];
        let mut dynamic_bytes = vec![0xA6; 64];
        let mut optional_hash = Some(Hash::new(b"confidential domain"));

        for _ in 0..2 {
            zeroize_value_for_confidential_discard(&mut selector);
            zeroize_value_for_confidential_discard(&mut amount);
            zeroize_value_for_confidential_discard(&mut fixed_bytes);
            zeroize_value_for_confidential_discard(&mut dynamic_bytes);
            zeroize_value_for_confidential_discard(&mut optional_hash);

            assert!(!selector);
            assert_eq!(amount, 0);
            assert_eq!(fixed_bytes, [0; 32]);
            assert!(dynamic_bytes.is_empty());
            assert!(optional_hash.is_none());
        }
    }
    #[test]
    fn invalid_private_key() {
        assert!(PrivateKey::from_hex(
            Algorithm::Ed25519,
            "0000000000000000000000000000000049BF70187154C57B97AF913163E8E875733B4EAF1F3F0689B31CE392129493E9"
        ).is_err());
        #[cfg(feature = "bls")]
        assert!(
            PrivateKey::from_hex(
                Algorithm::BlsNormal,
                "93CA389FC2979F3F7D2A7F8B76C70DE6D5EAF5FA58D4F93CB8B0FB298D398ACC59C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            ).is_err());
    }
    #[test]
    fn key_pair_mismatch() {
        KeyPair::new(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
                .parse()
                .expect("Public key not in mulithash format"),
            "8026203A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A"
                .parse()
                .expect("Public key not in mulithash format"),
        )
        .unwrap_err();
        #[cfg(feature = "bls")]
        {
            KeyPair::new("ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
                .parse()
                .expect("Public key not in mulithash format"),
                "892620CC176E44C41AA144FD1BEE4E0BCD2EF43F06D0C7BC2988E89A799951D240E503"
                .parse()
                .expect("Private key not in mulithash format"),
                ).unwrap_err();
        }
    }
    #[test]
    fn display_public_key() {
        assert_eq!(
            format!(
                "{}",
                PublicKey::from_hex(
                    Algorithm::Ed25519,
                    "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
                )
                .unwrap()
            ),
            "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey::from_hex(
                    Algorithm::Secp256k1,
                    "0312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
                )
                .unwrap()
            ),
            "e701210312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
        );
        #[cfg(feature = "bls")]
        {
            assert_eq!(
                format!(
                    "{}",
                    PublicKey::from_hex(
                        Algorithm::BlsNormal,
                        "9060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2",
                    ).unwrap()
                ),
                "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2",
            );
            assert_eq!(
                format!(
                    "{}",
                    PublicKey::from_hex(
                        Algorithm::BlsSmall,
                        "9051D4A9C69402423413EBBA4C00BC82A0102AA2B783057BD7BCEE4DD17B37DE5D719EE84BE43783F2AE47A673A74B8315DD3E595ED1FBDFAC17DA1D7A36F642B423ED18275FAFD671B1D331439D22F12FB6EB436A47E8656F182A78DF29D310",
                    ).unwrap()
                ),
                "eb01609051D4A9C69402423413EBBA4C00BC82A0102AA2B783057BD7BCEE4DD17B37DE5D719EE84BE43783F2AE47A673A74B8315DD3E595ED1FBDFAC17DA1D7A36F642B423ED18275FAFD671B1D331439D22F12FB6EB436A47E8656F182A78DF29D310",
            );
        }
    }
    #[derive(Debug, PartialEq)]
    struct TestJson {
        public_key: PublicKey,
        private_key: ExposedPrivateKey,
    }
    impl norito::json::JsonSerialize for TestJson {
        fn json_serialize(&self, out: &mut String) {
            use norito::json::{self, Map, Value};
            let mut map = Map::new();
            map.insert(
                "public_key".into(),
                json::to_value(&self.public_key).expect("serialize public key"),
            );
            map.insert(
                "private_key".into(),
                json::to_value(&self.private_key).expect("serialize private key"),
            );
            norito::json::JsonSerialize::json_serialize(&Value::Object(map), out);
        }
    }
    impl norito::json::JsonDeserialize for TestJson {
        fn json_deserialize(
            parser: &mut norito::json::Parser<'_>,
        ) -> Result<Self, norito::json::Error> {
            let mut map = norito::json::MapVisitor::new(parser)?;
            let mut public_key = None;
            let mut private_key = None;
            while let Some(key) = map.next_key()? {
                match key.as_str() {
                    "public_key" => {
                        if public_key.is_some() {
                            return Err(norito::json::MapVisitor::duplicate_field("public_key"));
                        }
                        public_key = Some(map.parse_value()?);
                    }
                    "private_key" => {
                        if private_key.is_some() {
                            return Err(norito::json::MapVisitor::duplicate_field("private_key"));
                        }
                        private_key = Some(map.parse_value()?);
                    }
                    _ => map.skip_value()?,
                }
            }
            map.finish()?;
            let public_key =
                public_key.ok_or_else(|| norito::json::MapVisitor::missing_field("public_key"))?;
            let private_key = private_key
                .ok_or_else(|| norito::json::MapVisitor::missing_field("private_key"))?;
            Ok(Self {
                public_key,
                private_key,
            })
        }
    }
    macro_rules! assert_test_json_serde {
        ($json:expr, $actual:expr) => {
            assert_eq!(
                norito::json::from_value::<TestJson>($json.clone()).expect("failed to deserialize"),
                $actual
            );
            assert_eq!(
                norito::json::to_value(&$actual).expect("failed to serialize"),
                $json
            );
        };
    }
    #[test]
    fn serde_keys_ed25519() {
        assert_test_json_serde!(
            norito::json!({
                "public_key": "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
                "private_key": "8026203A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A"
            }),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::Ed25519,
                    "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
                )
                .unwrap(),
                private_key: ExposedPrivateKey(
                    PrivateKey::from_hex(
                        Algorithm::Ed25519,
                        "3a7991af1abb77f3fd27cc148404a6ae4439d095a63591b77c788d53f708a02a",
                    )
                    .unwrap()
                )
            }
        );
    }
    #[test]
    fn serde_keys_secp256k1() {
        assert_test_json_serde!(
            norito::json!({
                "public_key": "e701210312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC",
                "private_key": "8126204DF4FCA10762D4B529FE40A2188A60CA4469D2C50A825B5F33ADC2CB78C69445"
            }),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::Secp256k1,
                    "0312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
                )
                .unwrap(),
                private_key: ExposedPrivateKey(
                    PrivateKey::from_hex(
                        Algorithm::Secp256k1,
                        "4DF4FCA10762D4B529FE40A2188A60CA4469D2C50A825B5F33ADC2CB78C69445",
                    )
                    .unwrap()
                )
            }
        );
    }
    fn assert_bounded_public_key_json(literal: &str, key: &PublicKey) {
        let encoded = format!("\"{literal}\"");
        assert_eq!(
            norito::json::to_json_bounded(key, encoded.len()).expect("exact bounded writer"),
            encoded
        );
        assert!(matches!(
            norito::json::to_json_bounded(key, encoded.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        ));
        let decoded: PublicKey = norito::json::from_str(&encoded).expect("bounded JSON decode");
        assert_eq!(&decoded, key);
        let limits = |bytes| {
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (_, usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            norito::json::from_str::<PublicKey>(&encoded)
        });
        let exact = usage.total_allocated_bytes();
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact), || {
            norito::json::from_str::<PublicKey>(&encoded)
        });
        assert_eq!(&decoded.expect("exact decode budget"), key);
        assert_eq!(usage.total_allocated_bytes(), exact);
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact - 1), || {
            norito::json::from_str::<PublicKey>(&encoded)
        });
        assert!(matches!(
            decoded,
            Err(norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert!(usage.total_allocated_bytes() < exact);
    }
    #[test]
    fn public_key_bounded_json_is_direct_and_measured() {
        let ed_literal = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
        let ed: PublicKey = ed_literal.parse().expect("Ed25519 fixture");
        assert_bounded_public_key_json(ed_literal, &ed);
        let secp_literal =
            "e701210312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC";
        let secp: PublicKey = secp_literal.parse().expect("Secp256k1 fixture");
        assert_bounded_public_key_json(secp_literal, &secp);
    }
    #[test]
    fn borrowed_public_key_object_key_preserves_checked_validation() {
        let malformed = PublicKey(PublicKeyCompact::new(Algorithm::Ed25519, &[]));
        let map = std::collections::BTreeMap::from([(&malformed, 1_u8)]);
        assert!(matches!(
            norito::json::to_json_bounded(&map, 256),
            Err(norito::json::BoundedJsonError::Unsupported)
        ));
    }
    #[test]
    fn public_key_value_and_map_key_decoders_do_not_stage_json_text() {
        use norito::json::JsonDeserialize as _;

        let literal = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
        let value = norito::json::Value::String(literal.to_owned());
        let payload_bytes = 32;
        let limits = || {
            norito::core::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                payload_bytes + 1,
                usize::MAX,
            )
        };
        let (from_value, usage) = norito::core::with_decode_limits_measured(limits(), || {
            PublicKey::json_from_value(&value)
        });
        assert_eq!(from_value.expect("PublicKey value").to_string(), literal);
        assert_eq!(usage.total_allocated_bytes(), payload_bytes + 1);

        let (from_key, usage) = norito::core::with_decode_limits_measured(limits(), || {
            <PublicKey as norito::json::JsonObjectKeyOwned>::from_json_key_text(literal)
        });
        assert_eq!(from_key.expect("PublicKey map key").to_string(), literal);
        assert_eq!(usage.total_allocated_bytes(), payload_bytes + 1);
        let public_key: PublicKey = literal.parse().expect("PublicKey fixture");
        let map = std::collections::BTreeMap::from([(&public_key, 5_u8)]);
        let expected = format!("{{\"{literal}\":5}}");
        assert_eq!(
            norito::json::to_json_bounded(&map, expected.len())
                .expect("serialize borrowed public-key map at exact bound"),
            expected
        );
        assert!(matches!(
            norito::json::to_json_bounded(&map, expected.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        ));
    }
    #[test]
    fn public_key_json_canonical_decoders_reject_prefixes_before_payload_allocation() {
        use norito::json::{self, JsonDeserialize as _, JsonObjectKeyOwned as _};

        type Map = std::collections::BTreeMap<PublicKey, u8>;
        let literal = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
        let zero_budget =
            || norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        for prefix in ["ed25519", "secp256k1"] {
            let alias = format!("{prefix}:{literal}");
            let value = json::Value::String(alias.clone());
            let (direct, usage) = norito::core::with_decode_limits_measured(zero_budget(), || {
                PublicKey::from_canonical_str_for_decode(&alias)
            });
            let error = direct.expect_err("prefixed public key must be rejected");
            assert!(matches!(
                &error,
                norito::core::Error::InvalidValue {
                    context: "public key"
                }
            ));
            assert_eq!(error.to_string(), "invalid public key");
            assert_eq!(usage.total_allocated_bytes(), 0);

            let (from_value, usage) =
                norito::core::with_decode_limits_measured(zero_budget(), || {
                    PublicKey::json_from_value(&value)
                });
            assert!(matches!(
                from_value,
                Err(json::Error::Message(message)) if message == "invalid public key"
            ));
            assert_eq!(usage.total_allocated_bytes(), 0);

            let (from_key, usage) =
                norito::core::with_decode_limits_measured(zero_budget(), || {
                    PublicKey::from_json_key_text(&alias)
                });
            assert!(matches!(
                from_key,
                Err(json::Error::Message(message)) if message == "invalid public key"
            ));
            assert_eq!(usage.total_allocated_bytes(), 0);

            let scalar = format!("\"{alias}\"");
            assert!(json::from_str::<PublicKey>(&scalar).is_err());
            let map = format!("{{\"{alias}\":7}}");
            assert!(json::from_str::<Map>(&map).is_err());
        }

        // A canonical key reaches payload admission on every borrowed path.
        let value = json::Value::String(literal.to_owned());
        let (direct, usage) = norito::core::with_decode_limits_measured(zero_budget(), || {
            PublicKey::from_canonical_str_for_decode(literal)
        });
        assert!(
            direct
                .expect_err("zero payload budget")
                .is_decode_resource_limit()
        );
        assert_eq!(usage.total_allocated_bytes(), 0);

        let (from_value, usage) = norito::core::with_decode_limits_measured(zero_budget(), || {
            PublicKey::json_from_value(&value)
        });
        assert!(matches!(
            from_value,
            Err(json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert_eq!(usage.total_allocated_bytes(), 0);

        let (from_key, usage) = norito::core::with_decode_limits_measured(zero_budget(), || {
            PublicKey::from_json_key_text(literal)
        });
        assert!(matches!(
            from_key,
            Err(json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert_eq!(usage.total_allocated_bytes(), 0);

        let public_key: PublicKey = literal.parse().expect("canonical public key fixture");
        let scalar = format!("\"{literal}\"");
        assert_eq!(
            json::from_str::<PublicKey>(&scalar).expect("canonical scalar"),
            public_key
        );
        let map = format!("{{\"{literal}\":7}}");
        assert_eq!(
            json::from_str::<Map>(&map).expect("canonical map"),
            Map::from([(public_key, 7)])
        );
    }
    #[test]
    fn public_key_json_object_key_map_contract_is_canonical_and_bounded() {
        use norito::json;
        type Map = std::collections::BTreeMap<PublicKey, u8>;
        let literal = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
        let public_key: PublicKey = literal.parse().expect("canonical public key fixture");
        let map = Map::from([(public_key, 7)]);
        let expected = format!("{{\"{literal}\":7}}");
        assert_eq!(json::to_json(&map).expect("public-key map"), expected);
        assert_eq!(
            json::from_str::<Map>(&expected).expect("public-key map roundtrip"),
            map
        );
        assert_eq!(
            json::to_json_bounded(&map, expected.len()).expect("exact map bound"),
            expected
        );
        assert!(matches!(
            json::to_json_bounded(&map, expected.len() - 1),
            Err(json::BoundedJsonError::BodyTooLarge)
        ));
        let escaped_key = format!("\\u0065{}", &literal[1..]);
        let escaped = format!("{{\"{escaped_key}\":7}}");
        assert_eq!(
            json::from_str::<Map>(&escaped).expect("escaped canonical public key"),
            map
        );
        for key in [
            format!("ed25519:{literal}"),
            literal.to_lowercase(),
            literal.to_uppercase(),
            format!(" {literal}"),
        ] {
            let encoded = format!("{{\"{key}\":7}}");
            assert!(
                json::from_str::<Map>(&encoded).is_err(),
                "noncanonical public-key map key must fail: {encoded}"
            );
        }
        for second_key in [literal.to_owned(), escaped_key] {
            let duplicate = format!("{{\"{literal}\":7,\"{second_key}\":8}}");
            assert!(
                json::from_str::<Map>(&duplicate).is_err(),
                "duplicate decoded public key must fail: {duplicate}"
            );
        }
    }
    #[test]
    fn public_key_json_rejects_above_protocol_literal_before_hex_decode() {
        let encoded = format!(
            "\"{}\"",
            "A".repeat(multihash::MAX_PUBLIC_KEY_LITERAL_BYTES + 1)
        );
        let error = norito::json::from_str::<PublicKey>(&encoded)
            .expect_err("above-protocol public-key literal must fail");
        assert!(
            matches!(error, norito::json::Error::Message(message) if message == "invalid public key")
        );
    }
    #[test]
    fn fromstr_accepts_algo_prefixed_public_key() {
        // Ed25519 example from existing tests
        let mh_hex = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
        let prefixed = format!("ed25519:{mh_hex}");
        let pk1: PublicKey = mh_hex.parse().expect("bare multihash parses");
        let pk2: PublicKey = prefixed.parse().expect("prefixed multihash parses");
        assert_eq!(pk1, pk2);
    }
    #[test]
    fn fromstr_accepts_algo_prefixed_private_key() {
        // Ed25519 example from existing tests
        let mh_hex = "8026203A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A";
        let prefixed = format!("ed25519:{mh_hex}");
        let sk1: PrivateKey = mh_hex.parse().expect("bare multihash parses");
        let sk2: PrivateKey = prefixed.parse().expect("prefixed multihash parses");
        assert_eq!(sk1.to_bytes().1, sk2.to_bytes().1);
        assert_eq!(sk1.algorithm(), sk2.algorithm());
    }
    #[test]
    fn key_generation_options_redact_secret_material_from_debug() {
        let seed = super::KeyGenOption::<()>::UseSeed(vec![0xA5; 32]);
        assert_eq!(format!("{seed:?}"), "UseSeed { len: 32 }");

        let private = super::KeyGenOption::FromPrivateKey("do-not-log-this-private-key");
        assert_eq!(format!("{private:?}"), "FromPrivateKey([REDACTED])");
    }
    #[test]
    fn prefixed_mismatch_is_error() {
        // Public key: try wrong prefix
        let mh_hex = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
        let wrong = format!("secp256k1:{mh_hex}");
        assert!(wrong.parse::<PublicKey>().is_err());
        // Private key: wrong prefix
        let mh_hex_sk = "8126204DF4FCA10762D4B529FE40A2188A60CA4469D2C50A825B5F33ADC2CB78C69445";
        let wrong_sk = format!("ed25519:{mh_hex_sk}");
        // This private key multihash above is secp256k1 in serde_keys_secp256k1 test
        assert!(wrong_sk.parse::<PrivateKey>().is_err());
    }
    #[test]
    #[cfg(feature = "bls")]
    fn serde_keys_bls() {
        assert_test_json_serde!(
            norito::json!({
                "public_key": "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2",
                "private_key": "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F"
            }),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::BlsNormal,
                    "9060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2",
                ).unwrap(),
                private_key: ExposedPrivateKey(PrivateKey::from_hex(
                    Algorithm::BlsNormal,
                    "1ca347641228c3b79aa43839dedc85fa51c0e8b9b6a00f6b0d6b0423e902973f",
                ).unwrap())
            }
        );
        assert_test_json_serde!(
            norito::json!({
                "public_key": "eb01609051D4A9C69402423413EBBA4C00BC82A0102AA2B783057BD7BCEE4DD17B37DE5D719EE84BE43783F2AE47A673A74B8315DD3E595ED1FBDFAC17DA1D7A36F642B423ED18275FAFD671B1D331439D22F12FB6EB436A47E8656F182A78DF29D310",
                "private_key": "8a26208CB95072914CDD8E4CF682FDBE1189CDF4FC54D445E760B3446F896DBDBF5B2B"
            }),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::BlsSmall,
                    "9051D4A9C69402423413EBBA4C00BC82A0102AA2B783057BD7BCEE4DD17B37DE5D719EE84BE43783F2AE47A673A74B8315DD3E595ED1FBDFAC17DA1D7A36F642B423ED18275FAFD671B1D331439D22F12FB6EB436A47E8656F182A78DF29D310",
                ).unwrap(),
                private_key: ExposedPrivateKey(PrivateKey::from_hex(
                    Algorithm::BlsSmall,
                    "8cb95072914cdd8e4cf682fdbe1189cdf4fc54d445e760b3446f896dbdbf5b2b",
                ).unwrap())
            }
        );
    }
}
