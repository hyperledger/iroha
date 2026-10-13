//! Exact initialized ML-KEM output custody and common-kernel controls.
use super::*;

fn seeded_rng() -> HedgedChaCha20Rng {
    deterministic_chacha20_rng(
        HedgedRngSeed::from_entropy([0x65; 32]),
        b"initialized-output",
    )
}

#[test]
fn initialized_outputs_match_original_backend_bytes_and_rng_for_every_suite() {
    for suite in MlKemSuite::ALL {
        let mut original_rng = seeded_rng();
        let mut coins = Zeroizing::new([0; 64]);
        original_rng.fill_bytes(&mut coins[..]);
        let mut expected_public = vec![0; suite.public_key_len()];
        let mut expected_secret = Zeroizing::new(vec![0; suite.secret_key_len()]);
        mlkem_ffi::keypair_derand(
            suite,
            &mut expected_public,
            &mut expected_secret[..],
            &coins,
        )
        .unwrap();
        suite
            .validate_key_pair(&expected_public, &expected_secret)
            .unwrap();

        let mut fixed_rng = seeded_rng();
        let mut public = [0xa5; MLKEM1024_PUBLIC_KEY_BYTES];
        let mut secret = Zeroizing::new([0xa5; MLKEM1024_SECRET_KEY_BYTES]);
        generate_mlkem_keypair_into(
            suite,
            &mut fixed_rng,
            &mut public[..suite.public_key_len()],
            &mut secret[..suite.secret_key_len()],
        )
        .unwrap();
        assert_eq!(&public[..suite.public_key_len()], &expected_public);
        assert_eq!(&secret[..suite.secret_key_len()], &expected_secret[..]);
        assert!(public[suite.public_key_len()..].iter().all(|b| *b == 0xa5));
        assert!(secret[suite.secret_key_len()..].iter().all(|b| *b == 0xa5));
        let owned = generate_mlkem_keypair(suite, &mut seeded_rng()).unwrap();
        assert_eq!(owned.public_key(), &public[..suite.public_key_len()]);
        assert_eq!(owned.secret_key(), &secret[..suite.secret_key_len()]);

        let mut encapsulation_coins = Zeroizing::new([0; 32]);
        original_rng.fill_bytes(&mut encapsulation_coins[..]);
        let mut expected_ciphertext = vec![0; suite.ciphertext_len()];
        let mut expected_shared = Zeroizing::new([0; 32]);
        mlkem_ffi::encapsulate_derand(
            suite,
            &mut expected_ciphertext,
            &mut expected_shared[..],
            &expected_public,
            &encapsulation_coins,
        )
        .unwrap();
        let mut ciphertext = [0xa5; MLKEM1024_CIPHERTEXT_BYTES];
        let mut shared = Zeroizing::new([0xa5; 32]);
        encapsulate_mlkem_into(
            suite,
            &public[..suite.public_key_len()],
            &mut fixed_rng,
            &mut shared[..],
            &mut ciphertext[..suite.ciphertext_len()],
        )
        .unwrap();
        assert_eq!(&ciphertext[..suite.ciphertext_len()], &expected_ciphertext);
        assert_eq!(*shared, *expected_shared);
        assert!(
            ciphertext[suite.ciphertext_len()..]
                .iter()
                .all(|b| *b == 0xa5)
        );
        let mut opened = Zeroizing::new([0; 32]);
        decapsulate_mlkem_into(
            suite,
            &secret[..suite.secret_key_len()],
            &ciphertext[..suite.ciphertext_len()],
            &mut opened[..],
        )
        .unwrap();
        assert_eq!(*opened, *shared);
        let owned_opened =
            decapsulate_mlkem(suite, &expected_secret, &expected_ciphertext).unwrap();
        assert_eq!(owned_opened.as_bytes(), &shared[..]);
        let mut original_next = [0; 64];
        let mut fixed_next = [0; 64];
        original_rng.fill_bytes(&mut original_next);
        fixed_rng.fill_bytes(&mut fixed_next);
        assert_eq!(
            original_next, fixed_next,
            "the exact random draw schedule remains unchanged"
        );
    }
}

#[test]
fn output_geometry_refuses_before_rng_and_erases_secret_without_neighbor_writes() {
    let suite = MlKemSuite::MlKem768;
    let mut rng = seeded_rng();
    let mut untouched_rng = seeded_rng();
    let mut public = [0xa5; MLKEM768_PUBLIC_KEY_BYTES];
    let mut secret = [0xa5; MLKEM768_SECRET_KEY_BYTES + 2];
    let err = generate_mlkem_keypair_into(
        suite,
        &mut rng,
        &mut public[..100],
        &mut secret[1..=MLKEM768_SECRET_KEY_BYTES],
    )
    .unwrap_err();
    assert!(matches!(err, MlKemError::BadEncoding { kind, .. } if kind == suite.public_key_kind()));
    assert!(public.iter().all(|b| *b == 0xa5));
    assert_eq!(secret[0], 0xa5);
    assert_eq!(secret[secret.len() - 1], 0xa5);
    assert!(secret[1..secret.len() - 1].iter().all(|b| *b == 0));
    assert_eq!(rng.next_u64(), untouched_rng.next_u64());

    let pair = generate_mlkem_keypair(suite, &mut seeded_rng()).unwrap();
    let mut shared = [0xa5; 32];
    let mut ciphertext = [0xa5; MLKEM768_CIPHERTEXT_BYTES];
    let err = encapsulate_mlkem_into(
        suite,
        &pair.public_key,
        &mut rng,
        &mut shared[..31],
        &mut ciphertext,
    )
    .unwrap_err();
    assert!(
        matches!(err, MlKemError::BadEncoding { kind, .. } if kind == suite.shared_secret_kind())
    );
    assert_eq!(shared[31], 0xa5);
    assert!(shared[..31].iter().all(|b| *b == 0));
    assert!(ciphertext.iter().all(|b| *b == 0xa5));
    assert_eq!(rng.next_u64(), untouched_rng.next_u64());
}

#[test]
fn initialized_outputs_preserve_input_error_order_and_erase_on_unwind() {
    let suite = MlKemSuite::MlKem768;
    let mut shared = [0xa5; 32];
    let err = encapsulate_mlkem_into(suite, &[0; 1], &mut seeded_rng(), &mut shared, &mut [0; 1])
        .unwrap_err();
    assert!(matches!(err, MlKemError::BadEncoding { kind, .. } if kind == suite.public_key_kind()));
    assert_eq!(shared, [0; 32]);
    shared.fill(0xa5);
    let err = decapsulate_mlkem_into(suite, &[0; 1], &[0; 1], &mut shared).unwrap_err();
    assert!(matches!(err, MlKemError::BadEncoding { kind, .. } if kind == suite.secret_key_kind()));
    assert_eq!(shared, [0; 32]);
    shared.fill(0xa5);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let output = SecretOutput::new(&mut shared);
        output.bytes.fill(0x71);
        panic!("partial backend output");
    }));
    assert!(unwind.is_err());
    assert_eq!(shared, [0; 32]);
}
