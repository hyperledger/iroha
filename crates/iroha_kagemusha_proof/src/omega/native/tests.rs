//! Frame/transport codec and recursive fold cancellation tests. Fabricated proof carriers
//! establish no operation admission; the cancellation case refuses before fold inputs.
use super::*;
use iroha_pasta::PastaAffine;
use iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR;

#[test]
fn terminal_fold_preserves_cancellation_at_recursive_boundary() {
    // This source-owned configuration is used by the actual closed terminal
    // wrapper. The direct recursion call below reaches its cancellation cut
    // without fabricating a verified terminal-frame authority.
    let params = PinnedParams::<Eq>::derive(1).unwrap();
    let cancellation = iroha_pasta::CancellationToken::new();
    let inputs = vec![opening(); 4];
    let tape = || {
        iroha_plonk_recursion::FoldTape::<Eq>::try_fill::<core::convert::Infallible>(|coin| {
            *coin = Fp::ONE;
            Ok(())
        })
        .unwrap()
    };
    for token in [None, Some(&cancellation)] {
        let config = terminal_fold_config(MemoryBudget::default(), token);
        assert!(matches!(
            iroha_plonk_recursion::create_fold(
                &params,
                &inputs,
                tape(),
                iroha_plonk_recursion::FoldPurpose::SigmaBatch,
                &config
            ),
            Err(iroha_plonk_recursion::Error::Parameters(_))
        ));
    }
    let config = terminal_fold_config(MemoryBudget::default(), Some(&cancellation));
    cancellation.cancel();
    assert!(matches!(
        iroha_plonk_recursion::create_fold(
            &params,
            &inputs,
            tape(),
            iroha_plonk_recursion::FoldPurpose::SigmaBatch,
            &config
        ),
        Err(iroha_plonk_recursion::Error::Cancelled)
    ));
}

fn frame() -> [Fp; 69] {
    let generator = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap();
    let (x, y) = generator.coordinates().unwrap();
    let coordinates: Vec<Fp> = [x, y]
        .into_iter()
        .flat_map(|value| foreign_limbs(&value).map(Fp::from_u128))
        .collect();
    let mut frame = [Fp::ZERO; 69];
    frame[1] = Fp::from(16);
    for (point, challenges) in [(2, 6), (22, 26), (42, 46)] {
        frame[point..point + 4].copy_from_slice(&coordinates);
        frame[challenges..challenges + K].fill(Fp::ONE);
    }
    frame[63] = Fp::ONE;
    frame[65..].copy_from_slice(&coordinates);
    frame
}
fn opening() -> FoldInput<Eq> {
    FoldInput::from_normalized(
        decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap(),
        16,
        [Fp::ONE; K],
    )
    .unwrap()
}

#[test]
fn frame_source_k_and_zero_prefix_are_exact() {
    let full = terminal_fold_inputs(&frame(), opening()).unwrap();
    assert_eq!(full[0].source_k(), 16);
    let mut short = frame();
    short[1] = Fp::from(12);
    short[6..10].fill(Fp::ZERO);
    let slots = terminal_fold_inputs(&short, opening()).unwrap();
    assert_eq!(slots[0].source_k(), 12);
    assert_eq!(&slots[0].challenges()[..4], &[Fp::ZERO; 4]);
    short[1] = Fp::from(15);
    assert_eq!(
        terminal_fold_inputs(&short, opening()).unwrap_err(),
        Error::Input
    );
    short[1] = Fp::from(12);
    short[9] = Fp::ONE;
    assert_eq!(
        terminal_fold_inputs(&short, opening()).unwrap_err(),
        Error::Input
    );
}

#[test]
fn frame_modes_are_one_hot_and_correction_must_change_original_point() {
    let mut frame = frame();
    let incoming = terminal_fold_inputs(&frame, opening()).unwrap();
    assert_eq!(incoming[3], opening());
    frame[62] = Fp::ONE;
    assert_eq!(
        terminal_fold_inputs(&frame, opening()).unwrap_err(),
        Error::Input
    );
    frame[62] = Fp::ZERO;
    frame[63] = Fp::ZERO;
    frame[64] = Fp::ONE;
    assert_eq!(
        terminal_fold_inputs(&frame, opening()).unwrap_err(),
        Error::Input
    );
    frame[64] = Fp::from(2);
    assert_eq!(
        terminal_fold_inputs(&frame, opening()).unwrap_err(),
        Error::Input
    );
}

#[test]
fn foreign_coordinate_codec_rejects_integer_and_modulus_aliases() {
    assert_eq!(native_u128(Fp::from_u128(u128::MAX)).unwrap(), u128::MAX);
    assert_eq!(native_u128(-Fp::ONE), Err(Error::Input));
    assert_eq!(foreign_coordinate(&[Fp::ZERO]), Err(Error::Input));
    assert_eq!(
        foreign_coordinate(&[Fp::from_u128(u128::MAX); 2]),
        Err(Error::Input)
    );
    assert_eq!(
        point(&[Fp::ZERO, Fp::ZERO, Fp::ONE, Fp::ZERO]),
        Err(Error::Input)
    );
}

#[test]
fn corrected_slot_retains_exact_incoming_challenges_and_distinct_point() {
    let mut frame = frame();
    let original = point(&frame[42..46]).unwrap();
    let corrected = -original;
    let (x, y) = corrected.coordinates().unwrap();
    let coordinates: Vec<_> = [x, y]
        .into_iter()
        .flat_map(|value| foreign_limbs(&value).map(Fp::from_u128))
        .collect();
    frame[65..].copy_from_slice(&coordinates);
    frame[63] = Fp::ZERO;
    frame[64] = Fp::ONE;
    frame[46] = Fp::from(7);
    let slots = terminal_fold_inputs(&frame, opening()).unwrap();
    assert_eq!(slots[3].g(), &corrected);
    assert_ne!(slots[3].g(), &original);
    assert_eq!(
        slots[3].challenges(),
        <&[Fp; K]>::try_from(&frame[46..62]).unwrap()
    );
    // This codec test does not decide this intentionally fabricated claim. Preparation
    // must independently reject it unless the complete native equality really holds.
}

#[test]
fn canonical_transport_preserves_distinct_source_claim_and_outer_opening() {
    let pallas = AccumulatorT::<Ep>::new(
        decode_point::<Ep>(&PALLAS_TRIVIAL_GENERATOR).unwrap(),
        [Fq::ONE; K],
    )
    .unwrap();
    let vesta = AccumulatorT::<Eq>::new(
        decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap(),
        [Fp::ONE; K],
    )
    .unwrap();
    let output = Output {
        proof: vec![0xa5; 3], // Codec stand-in only; never admitted by prepare or restore.
        instances: vec![vec![], vec![], vec![]],
        opening: pallas.as_input(),
        pallas: pallas.clone(),
        vesta: vesta.clone(),
    };
    let bytes = output.transport();
    assert_eq!(bytes.len(), 3 + 2 * ACCUMULATOR_BYTES);
    assert_eq!(&bytes[..3], &[0xa5; 3]);
    assert_eq!(&bytes[3..3 + ACCUMULATOR_BYTES], &pallas.to_bytes());
    assert_eq!(&bytes[3 + ACCUMULATOR_BYTES..], &vesta.to_bytes());
}

#[test]
fn rebuild_failure_preserves_cancellation_and_refuses_source_authority() {
    use iroha_plonk::keys::KeyError;
    assert_eq!(
        rebuild_error(&RebuildError::Key(KeyError::Cancelled)),
        Error::Cancelled
    );
    for error in [
        RebuildError::Profile,
        RebuildError::Source,
        RebuildError::Key(KeyError::Shape {
            what: "fixed rows",
            expected: 64,
            actual: 63,
        }),
    ] {
        assert_eq!(rebuild_error(&error), Error::Artifact);
    }
}

#[test]
fn identity_generator_frame_roundtrips_and_keeps_correction_distinctness() {
    let identity = iroha_plonk::transcript::decode_generator::<Eq>(&[0; 32]).unwrap();
    assert_eq!(point(&[Fp::ZERO; 4]).unwrap(), identity);
    let mut public = frame();
    public[2..6].fill(Fp::ZERO);
    public[22..26].fill(Fp::ZERO);
    public[42..46].fill(Fp::ZERO);
    let inputs = terminal_fold_inputs(&public, opening()).unwrap();
    assert_eq!(*inputs[0].g(), identity);
    assert_eq!(*inputs[2].g(), identity);
    // A correction to identity is allowed only when it changes the original G.
    public[63] = Fp::ZERO;
    public[64] = Fp::ONE;
    public[65..].fill(Fp::ZERO);
    assert_eq!(
        terminal_fold_inputs(&public, opening()).unwrap_err(),
        Error::Input
    );
    let finite = frame();
    public[42..46].copy_from_slice(&finite[42..46]);
    let corrected = terminal_fold_inputs(&public, opening()).unwrap();
    assert_eq!(*corrected[3].g(), identity);
    // Syntax never establishes the generator decision: this normalized identity is false.
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let false_claim = AccumulatorT::<Eq>::new(identity, [Fp::ONE; K]).unwrap();
    assert!(
        false_claim
            .decide(&params, MemoryBudget::default())
            .is_err()
    );
}
