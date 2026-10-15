//! Unadmitted DATA controls for the local checkpoint carrier grammar.
//!
//! No specimen is a proof, an installed key, a signed inventory or a session.
//! Genuine acceptance/round trips use the maintained Bootstrap originals in the
//! ignored `production_native_bootstrap_stages_preserve_the_genuine_installed_relation`.

use super::*;

// Only public grammar DATA: repeated pinned public points and zero scalar words.
// This is canonical syntax, never a valid fold, session, or source authority.
fn public_fold_data() -> PrivateFoldBytes {
    let mut bytes = [0_u8; FOLD_WITNESS_BYTES];
    for word in 0..=2 * iroha_plonk_recursion::K {
        bytes[word * 32..(word + 1) * 32]
            .copy_from_slice(&iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR);
    }
    let last = 32 * (2 * iroha_plonk_recursion::K + 2);
    bytes[last..last + 32].copy_from_slice(&iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR);
    PrivateFoldBytes::from_fold(
        FoldWitness::<super::super::Ep>::from_private_bytes(&bytes).unwrap(),
    )
}

fn data(kind: CheckpointKind) -> (CheckpointLayout, Payload, [u8; 32]) {
    // A bounded grammar specimen only; it never enters a native restore/prover.
    let layout = CheckpointLayout::new(kind, [1; 32], [2; 32], 64).unwrap();
    let context = [3; 32];
    let payload = Payload {
        version: 1,
        kind: kind.tag(),
        descriptor_digest: [1; 32],
        verifying_key_digest: [2; 32],
        source_context: context,
        proof: vec![4; layout.proof_bytes],
        vesta: (kind == CheckpointKind::Wrapper).then_some([5; ACCUMULATOR_BYTES]),
    };
    (layout, payload, context)
}

#[test]
fn unadmitted_bounded_data_round_trips_exact_bytes_under_the_counted_layout() {
    for kind in [CheckpointKind::First, CheckpointKind::Wrapper] {
        // This checks only the carrier grammar. These nonzero DATA bytes are
        // never passed to Session restore, a proof verifier or accumulator decide.
        let (layout, payload, context) = data(kind);
        let expected_proof = payload.proof.clone();
        let expected_vesta = payload.vesta;
        assert_eq!(
            norito::canonical_frame_len(&payload).unwrap(),
            layout.payload_bytes()
        );
        let bytes = payload.encode(&layout, context).unwrap();
        assert_eq!(bytes.len(), layout.payload_bytes());
        let restored = Payload::decode(&bytes, &layout, context).unwrap();
        assert_eq!(restored.version, 1);
        assert_eq!(restored.kind, kind.tag());
        assert_eq!(restored.descriptor_digest, *layout.descriptor_digest());
        assert_eq!(
            restored.verifying_key_digest,
            *layout.verifying_key_digest()
        );
        assert_eq!(restored.source_context, context);
        assert_eq!(restored.proof, expected_proof);
        assert_eq!(restored.vesta, expected_vesta);
        assert_eq!(restored.encode(&layout, context).unwrap(), bytes);
    }
}

#[test]
fn unadmitted_data_cannot_substitute_kind_source_or_installed_key_identity() {
    for kind in [CheckpointKind::First, CheckpointKind::Wrapper] {
        for mutation in 0..6 {
            let (layout, mut payload, context) = data(kind);
            match mutation {
                0 => payload.version = 2,
                1 => payload.kind ^= 1,
                2 => payload.descriptor_digest[0] ^= 1,
                3 => payload.verifying_key_digest[0] ^= 1,
                4 => payload.source_context[0] ^= 1,
                _ => payload.kind = u8::MAX,
            }
            // Re-encoding gives the mutated DATA a genuine codec checksum; its
            // altered identity must still be refused before proof verification.
            let bytes = norito::encode_canonical(&payload).unwrap();
            assert!(
                matches!(Payload::decode(&bytes, &layout, context), Err(Error::Input)),
                "{kind:?} mutation {mutation}"
            );
        }
    }
}

#[test]
fn unadmitted_data_cannot_add_drop_or_relabel_a_native_claim_or_proof_byte() {
    for kind in [CheckpointKind::First, CheckpointKind::Wrapper] {
        for mutation in 0..4 {
            let (layout, mut payload, context) = data(kind);
            match mutation {
                0 => {
                    payload.proof.pop();
                }
                1 => payload.proof.push(0),
                2 => {
                    payload.vesta = if payload.vesta.is_some() {
                        None
                    } else {
                        Some([0; ACCUMULATOR_BYTES])
                    }
                }
                _ => {
                    payload.kind ^= 1;
                    payload.vesta = if payload.vesta.is_some() {
                        None
                    } else {
                        Some([0; ACCUMULATOR_BYTES])
                    };
                }
            }
            let bytes = norito::encode_canonical(&payload).unwrap();
            assert!(
                matches!(Payload::decode(&bytes, &layout, context), Err(Error::Input)),
                "{kind:?} mutation {mutation}"
            );
        }
    }
}

#[test]
fn bounded_data_frames_refuse_empty_truncated_trailing_and_noncanonical_input() {
    for kind in [CheckpointKind::First, CheckpointKind::Wrapper] {
        let (layout, payload, context) = data(kind);
        let bytes = norito::encode_canonical(&payload).unwrap();
        let mut extra = bytes.clone();
        extra.push(0);
        for bad in [&[][..], &bytes[..bytes.len() - 1], &extra[..]] {
            assert!(matches!(
                Payload::decode(bad, &layout, context),
                Err(Error::Input)
            ));
        }
        let mut bad_header = bytes;
        bad_header[0] ^= 1;
        assert!(matches!(
            Payload::decode(&bad_header, &layout, context),
            Err(Error::Input)
        ));
    }
}

#[test]
fn impossible_installed_lengths_refuse_before_counting_allocation() {
    for kind in [
        CheckpointKind::First,
        CheckpointKind::Wrapper,
        CheckpointKind::Terminal,
    ] {
        for bytes in [0, usize::MAX] {
            assert!(matches!(
                CheckpointLayout::new(kind, [1; 32], [2; 32], bytes),
                Err(Error::Artifact)
            ));
        }
    }
}

#[test]
fn terminal_data_carrier_binds_exact_source_key_fold_and_original_length() {
    let layout = CheckpointLayout::new(CheckpointKind::Terminal, [1; 32], [2; 32], 64).unwrap();
    let context = [3; 32];
    let make = || TerminalPayload {
        version: 1,
        descriptor_digest: [1; 32],
        verifying_key_digest: [2; 32],
        source_context: context,
        fold: public_fold_data(),
        proof: vec![4; 64],
    };
    let original = make().encode(&layout, context).unwrap();
    assert_eq!(original.len(), layout.payload_bytes());
    let restored = TerminalPayload::decode(&original, &layout, context).unwrap();
    assert_eq!(restored.fold.as_slice(), public_fold_data().as_slice());
    assert_eq!(&*restored.encode(&layout, context).unwrap(), &*original);
    for mutation in 0..7 {
        let mut payload = make();
        match mutation {
            0 => payload.version = 2,
            1 => payload.descriptor_digest[0] ^= 1,
            2 => payload.verifying_key_digest[0] ^= 1,
            3 => payload.source_context[0] ^= 1,
            4 => payload.fold = PrivateFoldBytes::unknown(),
            5 => {
                payload.proof.pop();
            }
            _ => payload.proof.push(0),
        }
        let bytes = norito::encode_canonical(&payload).unwrap();
        assert!(
            TerminalPayload::decode(&bytes, &layout, context).is_err(),
            "mutation{mutation}"
        );
    }
    // This specimen contains only the public grammar DATA above.
    let mut extra = original.to_vec();
    extra.push(0);
    for bad in [&[][..], &original[..original.len() - 1], &extra[..]] {
        assert!(TerminalPayload::decode(bad, &layout, context).is_err());
    }
    let mut bad_header = original.to_vec();
    bad_header[0] ^= 1;
    assert!(TerminalPayload::decode(&bad_header, &layout, context).is_err());
    assert!(Payload::decode(&original, &layout, context).is_err());
    for kind in [CheckpointKind::First, CheckpointKind::Wrapper] {
        let (other_layout, other_payload, _) = data(kind);
        assert!(make().check(&other_layout, context).is_err());
        assert!(other_payload.check(&layout, context).is_err());
    }
}

#[test]
fn checkpoint_read_refusal_preserves_original_and_exact_retry() {
    for kind in [CheckpointKind::First, CheckpointKind::Wrapper] {
        let (layout, payload, context) = data(kind);
        let bytes = payload.encode(&layout, context).unwrap();
        for limits in [
            norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        ] {
            let error = norito::with_decode_limits_scope(limits, || {
                Payload::decode(&bytes, &layout, context)
            })
            .err()
            .expect("actual enclosing decoder refusal");
            let Error::DecodeResource(ref original) = error else {
                panic!("lost original checkpoint refusal: {error:?}")
            };
            assert_eq!(
                original.kind(),
                norito::core::DecodeLocalRefusalKind::EnclosingLimit
            );
            assert_eq!(error.clone(), error);
            assert!(!error.is_cancelled());
            assert!(std::error::Error::source(&error).is_some());
            assert_eq!(
                Payload::decode(&bytes, &layout, context)
                    .unwrap()
                    .encode(&layout, context)
                    .unwrap(),
                bytes
            );
            assert!(matches!(
                norito::with_decode_limits_scope(limits, || {
                    Payload::decode(&bytes[..bytes.len() - 1], &layout, context)
                }),
                Err(Error::Input)
            ));
        }
    }
}

#[test]
fn terminal_checkpoint_read_refusal_preserves_original_and_exact_retry() {
    // Grammar-only data, never an admitted terminal or proof.
    let layout = CheckpointLayout::new(CheckpointKind::Terminal, [1; 32], [2; 32], 64).unwrap();
    let context = [3; 32];
    let payload = TerminalPayload {
        version: 1,
        descriptor_digest: [1; 32],
        verifying_key_digest: [2; 32],
        source_context: context,
        fold: public_fold_data(),
        proof: vec![4; 64],
    };
    let bytes = payload.encode(&layout, context).unwrap();
    for limits in [
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
    ] {
        let error = norito::with_decode_limits_scope(limits, || {
            TerminalPayload::decode(&bytes, &layout, context)
        })
        .err()
        .expect("actual enclosing decoder refusal");
        let Error::DecodeResource(ref original) = error else {
            panic!("lost original terminal checkpoint refusal: {error:?}")
        };
        assert_eq!(
            original.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
        assert_eq!(error.clone(), error);
        assert!(!error.is_cancelled());
        assert!(std::error::Error::source(&error).is_some());
        let retried = TerminalPayload::decode(&bytes, &layout, context)
            .unwrap()
            .encode(&layout, context)
            .unwrap();
        assert_eq!(&*retried, &*bytes);
        assert!(matches!(
            norito::with_decode_limits_scope(limits, || {
                TerminalPayload::decode(&bytes[..bytes.len() - 1], &layout, context)
            }),
            Err(Error::Input)
        ));
    }
}

#[test]
fn terminal_checkpoint_rejects_retired_salt_layout() {
    // Explicitly retained only as a denylist specimen. No old decoder exists.
    #[derive(NoritoSerialize, NoritoSchema)]
    #[norito_schema(name = "iroha.kagemusha.native.bootstrap.terminal_checkpoint.v1")]
    struct RetiredSaltData {
        version: u16,
        descriptor_digest: [u8; 32],
        verifying_key_digest: [u8; 32],
        source_context: [u8; 32],
        fold_salt: [u8; 32],
        proof: Vec<u8>,
    }
    let layout = CheckpointLayout::new(CheckpointKind::Terminal, [1; 32], [2; 32], 64).unwrap();
    let old = RetiredSaltData {
        version: 1,
        descriptor_digest: [1; 32],
        verifying_key_digest: [2; 32],
        source_context: [3; 32],
        fold_salt: [0; 32],
        proof: vec![4; 64],
    };
    let bytes = norito::encode_canonical(&old).unwrap();
    assert_ne!(bytes.len(), layout.payload_bytes());
    assert!(matches!(
        TerminalPayload::decode(&bytes, &layout, [3; 32]),
        Err(Error::Input)
    ));
}

#[test]
fn guarded_terminal_output_refuses_wrong_extent_and_does_not_consume_original() {
    let layout = CheckpointLayout::new(CheckpointKind::Terminal, [1; 32], [2; 32], 64).unwrap();
    let make = || TerminalPayload {
        version: 1,
        descriptor_digest: [1; 32],
        verifying_key_digest: [2; 32],
        source_context: [3; 32],
        fold: public_fold_data(),
        proof: vec![4; 64],
    };
    let original = make().encode(&layout, [3; 32]).unwrap();
    for delta in [-1_isize, 1] {
        let mut wrong = layout;
        wrong.payload_bytes = wrong.payload_bytes.checked_add_signed(delta).unwrap();
        assert!(matches!(make().encode(&wrong, [3; 32]), Err(Error::Input)));
    }
    let retried = TerminalPayload::decode(&original, &layout, [3; 32])
        .unwrap()
        .encode(&layout, [3; 32])
        .unwrap();
    assert_eq!(&*retried, &*original);
}
