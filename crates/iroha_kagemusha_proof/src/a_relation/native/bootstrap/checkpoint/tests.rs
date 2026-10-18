//! Unadmitted DATA controls for the local terminal checkpoint carrier grammar.
//!
//! No specimen is a proof, an installed key, a signed inventory or a session.
//! Genuine acceptance/round trips use the maintained Bootstrap originals in the
//! ignored `production_native_bootstrap_terminal_preserves_the_genuine_installed_relation`.

use super::*;
use crate::private_fold::PrivateFoldBytes;
use iroha_plonk_recursion::{ACCUMULATOR_BYTES, FOLD_WITNESS_BYTES, FoldWitness};

// A bounded grammar specimen only; it never enters a native restore/prover.
fn layout() -> CheckpointLayout {
    CheckpointLayout::new([1; 32], [2; 32], 64).unwrap()
}

fn data() -> Payload {
    Payload {
        version: 1,
        descriptor_digest: [1; 32],
        verifying_key_digest: [2; 32],
        source_context: [3; 32],
        proof: vec![4; 64],
    }
}

// Only public grammar DATA: repeated pinned public points and zero scalar words.
// This is canonical syntax for a retired layout, never a valid fold or session.
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

#[test]
fn unadmitted_bounded_data_round_trips_exact_bytes_under_the_counted_layout() {
    // This checks only the carrier grammar. These nonzero DATA bytes are never
    // passed to Session restore, a proof verifier or an accumulator decide.
    let layout = layout();
    let context = [3; 32];
    let payload = data();
    assert_eq!(
        norito::canonical_frame_len(&payload).unwrap(),
        layout.payload_bytes()
    );
    let bytes = payload.encode(&layout, context).unwrap();
    assert_eq!(bytes.len(), layout.payload_bytes());
    let restored = Payload::decode(&bytes, &layout, context).unwrap();
    assert_eq!(restored.version, 1);
    assert_eq!(restored.descriptor_digest, *layout.descriptor_digest());
    assert_eq!(
        restored.verifying_key_digest,
        *layout.verifying_key_digest()
    );
    assert_eq!(restored.source_context, context);
    assert_eq!(restored.proof, vec![4; layout.proof_bytes()]);
    assert_eq!(restored.encode(&layout, context).unwrap(), bytes);
}

#[test]
fn unadmitted_data_cannot_substitute_source_installed_key_or_proof_length() {
    let layout = layout();
    let context = [3; 32];
    for mutation in 0..6 {
        let mut payload = data();
        match mutation {
            0 => payload.version = 2,
            1 => payload.descriptor_digest[0] ^= 1,
            2 => payload.verifying_key_digest[0] ^= 1,
            3 => payload.source_context[0] ^= 1,
            4 => {
                payload.proof.pop();
            }
            _ => payload.proof.push(0),
        }
        // Re-encoding gives the mutated DATA a genuine codec checksum; its
        // altered identity must still be refused before proof verification.
        let bytes = norito::encode_canonical(&payload).unwrap();
        assert!(
            matches!(Payload::decode(&bytes, &layout, context), Err(Error::Input)),
            "mutation {mutation}"
        );
    }
    // The session's own source context is part of the exact accepted identity.
    assert!(matches!(data().encode(&layout, [9; 32]), Err(Error::Input)));
}

#[test]
fn bounded_data_frames_refuse_empty_truncated_trailing_and_noncanonical_input() {
    let layout = layout();
    let context = [3; 32];
    let bytes = norito::encode_canonical(&data()).unwrap();
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

#[test]
fn impossible_installed_lengths_refuse_before_counting_allocation() {
    for bytes in [0, usize::MAX] {
        assert!(matches!(
            CheckpointLayout::new([1; 32], [2; 32], bytes),
            Err(Error::Artifact)
        ));
    }
}

#[test]
fn checkpoint_read_refusal_preserves_original_and_exact_retry() {
    let layout = layout();
    let context = [3; 32];
    let bytes = data().encode(&layout, context).unwrap();
    for limits in [
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
    ] {
        let error =
            norito::with_decode_limits_scope(limits, || Payload::decode(&bytes, &layout, context))
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
        // Exact extent is checked before a decoder observer is entered.
        assert!(matches!(
            norito::with_decode_limits_scope(limits, || {
                Payload::decode(&bytes[..bytes.len() - 1], &layout, context)
            }),
            Err(Error::Input)
        ));
    }
}

#[test]
fn terminal_checkpoint_rejects_every_retired_bootstrap_layout() {
    // Explicitly retained only as denylist specimens. No old decoder exists: the
    // split A1/W0 carrier, the fold-carrying terminal and the salted terminal.
    #[derive(NoritoSerialize, NoritoSchema)]
    #[norito_schema(name = "iroha.kagemusha.native.bootstrap.checkpoint.v1")]
    struct RetiredStageData {
        version: u16,
        kind: u8,
        descriptor_digest: [u8; 32],
        verifying_key_digest: [u8; 32],
        source_context: [u8; 32],
        proof: Vec<u8>,
        vesta: Option<[u8; ACCUMULATOR_BYTES]>,
    }
    #[derive(NoritoSerialize, NoritoSchema)]
    #[norito_schema(name = "iroha.kagemusha.native.bootstrap.terminal_checkpoint.v1")]
    struct RetiredFoldData {
        version: u16,
        descriptor_digest: [u8; 32],
        verifying_key_digest: [u8; 32],
        source_context: [u8; 32],
        fold: PrivateFoldBytes,
        proof: Vec<u8>,
    }
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
    let layout = layout();
    let retired = [
        norito::encode_canonical(&RetiredStageData {
            version: 1,
            kind: 0,
            descriptor_digest: [1; 32],
            verifying_key_digest: [2; 32],
            source_context: [3; 32],
            proof: vec![4; 64],
            vesta: None,
        })
        .unwrap(),
        norito::encode_canonical(&RetiredStageData {
            version: 1,
            kind: 1,
            descriptor_digest: [1; 32],
            verifying_key_digest: [2; 32],
            source_context: [3; 32],
            proof: vec![4; 64],
            vesta: Some([5; ACCUMULATOR_BYTES]),
        })
        .unwrap(),
        norito::encode_canonical(&RetiredFoldData {
            version: 1,
            descriptor_digest: [1; 32],
            verifying_key_digest: [2; 32],
            source_context: [3; 32],
            fold: public_fold_data(),
            proof: vec![4; 64],
        })
        .unwrap(),
        norito::encode_canonical(&RetiredSaltData {
            version: 1,
            descriptor_digest: [1; 32],
            verifying_key_digest: [2; 32],
            source_context: [3; 32],
            fold_salt: [0; 32],
            proof: vec![4; 64],
        })
        .unwrap(),
    ];
    for (index, bytes) in retired.iter().enumerate() {
        assert_ne!(
            bytes.len(),
            layout.payload_bytes(),
            "retired layout {index}"
        );
        assert!(
            matches!(Payload::decode(bytes, &layout, [3; 32]), Err(Error::Input)),
            "retired layout {index}"
        );
    }
}

#[test]
fn guarded_output_refuses_wrong_extent_and_does_not_consume_original() {
    let layout = layout();
    let original = data().encode(&layout, [3; 32]).unwrap();
    for delta in [-1_isize, 1] {
        let mut wrong = layout;
        wrong.payload_bytes = wrong.payload_bytes.checked_add_signed(delta).unwrap();
        assert!(matches!(data().encode(&wrong, [3; 32]), Err(Error::Input)));
    }
    let retried = Payload::decode(&original, &layout, [3; 32])
        .unwrap()
        .encode(&layout, [3; 32])
        .unwrap();
    assert_eq!(retried, original);
}
