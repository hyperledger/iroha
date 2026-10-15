//! Retained-source ownership and cancellation controls using public syntax DATA.
use super::*;
use iroha_plonk::transcript::decode_point;
use iroha_plonk_recursion::{FOLD_WITNESS_BYTES, K, VESTA_TRIVIAL_GENERATOR};

fn specimen() -> crate::private_fold::PrivateFoldBytes {
    // Deliberately public, non-deciding grammar DATA, never secret entropy.
    let mut raw = [0_u8; FOLD_WITNESS_BYTES];
    for word in 0..=2 * K {
        raw[word * 32..(word + 1) * 32].copy_from_slice(&VESTA_TRIVIAL_GENERATOR);
    }
    let last = 32 * (2 * K + 2);
    raw[last..last + 32].copy_from_slice(&VESTA_TRIVIAL_GENERATOR);
    crate::private_fold::PrivateFoldBytes::from_fold(
        FoldWitness::<Eq>::from_private_bytes(&raw).unwrap(),
    )
}

#[test]
fn route_presence_requires_exact_private_source_kind() {
    assert!(QSigmaFoldSource::NoIncoming.check_presence(false).is_ok());
    assert!(matches!(
        QSigmaFoldSource::NoIncoming.check_presence(true),
        Err(QSigmaError::FoldSource)
    ));
    let bytes = specimen();
    assert!(
        QSigmaFoldSource::Retained(&bytes)
            .check_presence(true)
            .is_ok()
    );
    assert!(matches!(
        QSigmaFoldSource::Retained(&bytes).check_presence(false),
        Err(QSigmaError::FoldSource)
    ));
    let tape = FoldTape::<Eq>::try_fill::<core::convert::Infallible>(|word| {
        *word = Fp::ONE;
        Ok(())
    })
    .unwrap();
    let fresh = QSigmaFoldSource::Fresh(tape);
    assert!(fresh.check_presence(true).is_ok());
    assert!(matches!(
        fresh.check_presence(false),
        Err(QSigmaError::FoldSource)
    ));
    assert!(!QSigmaError::FoldSource.is_cancelled());
}

#[test]
fn retained_verification_keeps_original_and_cancellation() {
    let bytes = specimen();
    let original = bytes.clone();
    let params = PinnedParams::<Eq>::derive(1).unwrap();
    let point = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap();
    let input = FoldInput::from_opening(point, &[Fp::ONE; K]).unwrap();
    let inputs = [input.clone(), input.clone(), input];
    assert!(matches!(
        QSigmaFoldSource::NoIncoming.resolve(&params, &inputs, &FoldConfig::default()),
        Err(QSigmaError::FoldSource)
    ));
    assert!(matches!(
        QSigmaFoldSource::Retained(&bytes).resolve(&params, &inputs, &FoldConfig::default()),
        Err(QSigmaError::Fold(iroha_plonk_recursion::Error::Parameters(
            _
        )))
    ));
    let cancellation = iroha_pasta::CancellationToken::new();
    cancellation.cancel();
    let config = FoldConfig {
        cancellation: Some(cancellation),
        ..FoldConfig::default()
    };
    assert!(
        QSigmaFoldSource::Retained(&bytes)
            .resolve(&params, &inputs, &config)
            .unwrap_err()
            .is_cancelled()
    );
    assert_eq!(bytes.as_slice(), original.as_slice());
    assert_eq!(bytes.as_slice().as_ptr(), original.as_slice().as_ptr());
    let malformed = crate::private_fold::PrivateFoldBytes::unknown();
    assert!(
        QSigmaFoldSource::Retained(&malformed)
            .resolve(&params, &inputs, &FoldConfig::default())
            .is_err()
    );
}

#[test]
#[ignore = "genuine k16 fold and independent decision; run optimized"]
fn genuine_fresh_and_retained_q_fold_match_without_new_entropy() {
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let config = FoldConfig::default();
    let deciding = AccumulatorT::trivial(&params, config.kernel_budget).unwrap();
    let inputs = [
        deciding.as_input(),
        deciding.as_input(),
        deciding.as_input(),
    ];
    // Public deterministic component DATA, not a production entropy source.
    let mut next = 731_u64;
    let tape = FoldTape::<Eq>::try_fill::<core::convert::Infallible>(|word| {
        *word = Fp::from(next);
        next += 1;
        Ok(())
    })
    .unwrap();
    let (original, fresh) = QSigmaFoldSource::Fresh(tape)
        .resolve(&params, &inputs, &config)
        .unwrap();
    let (retained, restored) = QSigmaFoldSource::Retained(&original)
        .resolve(&params, &inputs, &config)
        .unwrap();
    assert_eq!(fresh, restored);
    assert_eq!(original.as_slice(), retained.as_slice());
    assert_eq!(original.as_slice().as_ptr(), retained.as_slice().as_ptr());
    let changed = iroha_plonk_recursion::PrivateWitnessBytes::try_write::<std::io::Error>(
        original.len(),
        |writer| {
            writer.write_all(&[original[0] ^ 1])?;
            writer.write_all(&original[1..])
        },
    )
    .unwrap();
    let changed = crate::private_fold::PrivateFoldBytes::from_owned(changed);
    assert!(
        QSigmaFoldSource::Retained(&changed)
            .resolve(&params, &inputs, &config)
            .is_err()
    );
    let mut different_inputs = inputs.clone();
    let mut challenges = *deciding.challenges();
    challenges[0] += Fp::ONE;
    different_inputs[0] = FoldInput::from_opening(*deciding.g(), &challenges).unwrap();
    assert!(
        QSigmaFoldSource::Retained(&original)
            .resolve(&params, &different_inputs, &config)
            .is_err()
    );
    assert_eq!(original.as_slice(), retained.as_slice());
}
