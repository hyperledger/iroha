//! Unadmitted DATA controls for the local checkpoint carrier grammar.
//!
//! No specimen is a proof, an installed key, a signed inventory or a session.
//! Genuine acceptance/round trips use the maintained Bootstrap originals in the
//! ignored `production_native_bootstrap_stages_preserve_the_genuine_installed_relation`.

use super::*;

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
fn terminal_data_carrier_binds_exact_source_key_salt_and_original_length() {
    let layout = CheckpointLayout::new(CheckpointKind::Terminal, [1; 32], [2; 32], 64).unwrap();
    let context = [3; 32];
    let make = || TerminalPayload {
        version: 1,
        descriptor_digest: [1; 32],
        verifying_key_digest: [2; 32],
        source_context: context,
        fold_salt: super::super::Fp::from(7).to_repr(),
        proof: vec![4; 64],
    };
    let original = make().encode(&layout, context).unwrap();
    assert_eq!(original.len(), layout.payload_bytes());
    assert_eq!(
        TerminalPayload::decode(&original, &layout, context)
            .unwrap()
            .encode(&layout, context)
            .unwrap(),
        original
    );
    for mutation in 0..7 {
        let mut payload = make();
        match mutation {
            0 => payload.version = 2,
            1 => payload.descriptor_digest[0] ^= 1,
            2 => payload.verifying_key_digest[0] ^= 1,
            3 => payload.source_context[0] ^= 1,
            4 => payload.fold_salt = [255; 32],
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
    let mut extra = original.clone();
    extra.push(0);
    for bad in [&[][..], &original[..original.len() - 1], &extra[..]] {
        assert!(TerminalPayload::decode(bad, &layout, context).is_err());
    }
    let mut bad_header = original.clone();
    bad_header[0] ^= 1;
    assert!(TerminalPayload::decode(&bad_header, &layout, context).is_err());
    assert!(Payload::decode(&original, &layout, context).is_err());
    for kind in [CheckpointKind::First, CheckpointKind::Wrapper] {
        let (other_layout, other_payload, _) = data(kind);
        assert!(make().check(&other_layout, context).is_err());
        assert!(other_payload.check(&layout, context).is_err());
    }
}
