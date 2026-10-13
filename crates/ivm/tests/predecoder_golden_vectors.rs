//! Predecoder golden vectors for the wide 32-bit encoding. These assertions ensure the cached
//! decode stream preserves instruction words and lengths across metadata variations.
use ivm::{ProgramMetadata, VMError, encoding, instruction, ivm_cache::IvmCache, ivm_mode};
fn push_word(buf: &mut Vec<u8>, word: u32) {
    buf.extend_from_slice(&word.to_le_bytes());
}
fn build_wide_code() -> Vec<u8> {
    let mut code = Vec::new();
    push_word(
        &mut code,
        encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 1, 2, 3),
    );
    push_word(
        &mut code,
        encoding::wide::encode_rr(instruction::wide::arithmetic::SUB, 4, 5, 6),
    );
    push_word(
        &mut code,
        encoding::wide::encode_rr(instruction::wide::arithmetic::XOR, 7, 8, 9),
    );
    push_word(
        &mut code,
        encoding::wide::encode_branch(instruction::wide::control::BEQ, 1, 4, 1),
    );
    // Filler that the branch would skip at runtime.
    push_word(
        &mut code,
        encoding::wide::encode_rr(instruction::wide::arithmetic::AND, 10, 10, 10),
    );
    push_word(&mut code, encoding::wide::encode_halt());
    code
}
#[test]
fn decode_stream_matches_expected_words_and_lengths() {
    let _lease = crate::predecode_test_support::exclusive();
    let code = build_wide_code();
    let decoded = IvmCache::decode_stream(&code).expect("decode ok");
    assert_eq!(decoded.len(), 6);
    let expected = [
        encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 1, 2, 3),
        encoding::wide::encode_rr(instruction::wide::arithmetic::SUB, 4, 5, 6),
        encoding::wide::encode_rr(instruction::wide::arithmetic::XOR, 7, 8, 9),
        encoding::wide::encode_branch(instruction::wide::control::BEQ, 1, 4, 1),
        encoding::wide::encode_rr(instruction::wide::arithmetic::AND, 10, 10, 10),
        encoding::wide::encode_halt(),
    ];
    for (idx, op) in decoded.iter().enumerate() {
        assert_eq!(op.pc, (idx * 4) as u64);
        assert_eq!(op.inst, expected[idx], "opcode {idx} word mismatch");
    }
}
#[test]
fn decode_stream_preserves_indexed_literal_and_compact_transfer_words() {
    let _lease = crate::predecode_test_support::exclusive();
    let expected = [
        encoding::wide::encode_literal(instruction::wide::memory::LDLIT, 12, 0x3456),
        encoding::wide::encode_literal(instruction::wide::memory::LDI64, 13, 0xabcd),
        encoding::wide::encode_offset24(instruction::wide::control::JALS, -2),
    ];
    let mut code = Vec::new();
    for word in expected {
        push_word(&mut code, word);
    }
    let decoded = IvmCache::decode_stream(&code).expect("decode compact extension words");
    assert_eq!(decoded.len(), expected.len());
    for (index, op) in decoded.iter().enumerate() {
        assert_eq!(op.pc, (index * 4) as u64);
        assert_eq!(op.inst, expected[index]);
    }
}
/// Decoding should ignore metadata fields that are orthogonal to the byte stream.
#[test]
fn decode_artifact_invariant_across_metadata_fields() {
    let _lease = crate::predecode_test_support::exclusive();
    let code = build_wide_code();
    // Baseline header
    let base = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let decode = |m: &ProgramMetadata| {
        let mut a = m.encode();
        a.extend_from_slice(&code);
        let (_meta, d) = IvmCache::decode_artifact(&a).expect("artifact decode ok");
        d
    };
    let golden = decode(&base);
    for mode in [
        0,
        ivm_mode::ZK,
        ivm_mode::VECTOR,
        ivm_mode::ZK | ivm_mode::VECTOR,
    ] {
        let mut m = base.clone();
        m.mode = mode;
        assert_eq!(&*golden, &*decode(&m), "mode 0x{mode:02x}");
    }
    for vlen in [0u8, 1, 4, 8, 16, 32, 64] {
        let mut m = base.clone();
        m.vector_length = vlen;
        assert_eq!(&*golden, &*decode(&m), "vlen {vlen}");
    }
    for cyc in [0u64, 1, 10, 1_000, u32::MAX as u64, u64::from(u32::MAX) + 1] {
        let mut m = base.clone();
        m.max_cycles = cyc;
        assert_eq!(&*golden, &*decode(&m), "cycles {cyc}");
    }
    let mut m = base.clone();
    m.abi_version = 1;
    assert_eq!(&*golden, &*decode(&m), "abi 1");
    let mut m = base.clone();
    m.vector_length = 65;
    let mut artifact = m.encode();
    artifact.extend_from_slice(&code);
    let err = IvmCache::decode_artifact(&artifact).expect_err("oversize vector length rejects");
    assert!(match (
        &(err),
        &(VMError::ProgramVectorLengthTooLarge {
            vector_length: 65,
            max_allowed: ivm::VECTOR_LENGTH_MAX,
        })
    ) {
        (
            VMError::ProgramVectorLengthTooLarge {
                vector_length: actual_field_0,
                max_allowed: actual_field_1,
            },
            VMError::ProgramVectorLengthTooLarge {
                vector_length: expected_field_0,
                max_allowed: expected_field_1,
            },
        ) => actual_field_0 == expected_field_0 && actual_field_1 == expected_field_1,
        _ => false,
    });
}
#[test]
fn decode_artifact_rejects_retired_or_unknown_minor_version() {
    let _lease = crate::predecode_test_support::exclusive();
    let code = build_wide_code();
    let base = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let mut retired = base.clone();
    retired.version_minor = 0;
    let mut retired_artifact = retired.encode();
    retired_artifact.extend_from_slice(&code);
    assert!(match (
        &(IvmCache::decode_artifact(&retired_artifact)
            .expect_err("the sole header policy rejects retired 1.0 artifacts")),
        &(VMError::UnsupportedProgramVersion { major: 1, minor: 0 })
    ) {
        (
            VMError::UnsupportedProgramVersion {
                major: actual_field_0,
                minor: actual_field_1,
            },
            VMError::UnsupportedProgramVersion {
                major: expected_field_0,
                minor: expected_field_1,
            },
        ) => actual_field_0 == expected_field_0 && actual_field_1 == expected_field_1,
        _ => false,
    });
    for vmin in [2u8, 7, 42] {
        let mut m = base.clone();
        m.version_minor = vmin;
        let mut artifact = m.encode();
        artifact.extend_from_slice(&code);
        let err = IvmCache::decode_artifact(&artifact).expect_err("invalid minor should reject");
        assert!(
            match (
                &(err),
                &(VMError::UnsupportedProgramVersion {
                    major: 1,
                    minor: vmin,
                })
            ) {
                (
                    VMError::UnsupportedProgramVersion {
                        major: actual_field_0,
                        minor: actual_field_1,
                    },
                    VMError::UnsupportedProgramVersion {
                        major: expected_field_0,
                        minor: expected_field_1,
                    },
                ) => actual_field_0 == expected_field_0 && actual_field_1 == expected_field_1,
                _ => false,
            },
            "minor {vmin}"
        );
    }
}
