//! Tests for IVM bytecode header (ProgramMetadata) validation.
use ivm::{ProgramMetadata, VMError, ivm_mode};
mod common;
fn encode_with(mut meta: ProgramMetadata, f: impl FnOnce(&mut ProgramMetadata)) -> Vec<u8> {
    f(&mut meta);
    meta.encode()
}
fn minimal_contract_artifact() -> Vec<u8> {
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        permissions: Vec::new(),
        events: Vec::new(),
        callables: vec![common::unit_callable(0)],
        seiyaku_name: "TestContract".to_owned(),
        compiler_fingerprint: "metadata-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: "main".to_owned(),
            kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(ivm_abi::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization:
                iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        enum_types: Vec::new(),
        states: Vec::new(),
    };
    let mut bytes = meta.encode();
    bytes.extend_from_slice(&interface.encode_section());
    for word in common::unit_return_words() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn minimal_contract_artifact_with_debug() -> Vec<u8> {
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        permissions: Vec::new(),
        events: Vec::new(),
        callables: vec![common::unit_callable(0)],
        seiyaku_name: "TestContract".to_owned(),
        compiler_fingerprint: "metadata-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: "main".to_owned(),
            kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(ivm_abi::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization:
                iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        enum_types: Vec::new(),
        states: Vec::new(),
    };
    let debug = ivm::EmbeddedContractDebugInfoV1 {
        source_map: vec![ivm::EmbeddedSourceMapEntryV1 {
            function_name: "main".to_owned(),
            pc_start: 0,
            pc_end: 16,
            source: ivm::EmbeddedSourceLocation {
                source_path: Some("contracts/demo.ko".to_owned()),
                source_id: 1,
                byte_start: 10,
                byte_end: 14,
                line: 2,
                column: 3,
            },
        }],
        budget_report: vec![ivm::EmbeddedFunctionBudgetReportV1 {
            function_name: "main".to_owned(),
            pc_start: 0,
            pc_end: 16,
            bytecode_bytes: 16,
            bytecode_words: 4,
            frame_bytes: 0,
            jump_span_words: 1,
            jump_range_risk: false,
            source: Some(ivm::EmbeddedSourceLocation {
                source_path: Some("contracts/demo.ko".to_owned()),
                source_id: 1,
                byte_start: 10,
                byte_end: 14,
                line: 2,
                column: 3,
            }),
        }],
    };
    let mut bytes = meta.encode();
    bytes.extend_from_slice(&interface.encode_section());
    bytes.extend_from_slice(&debug.encode_section());
    for word in common::unit_return_words() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}
#[test]
fn parse_accepts_valid_default_header() {
    let meta = ProgramMetadata::default();
    let bytes = meta.encode();
    let parsed = ProgramMetadata::parse(&bytes).expect("parse valid header");
    assert_eq!(parsed.code_offset, bytes.len());
    assert_eq!(parsed.header_len, 49);
    assert_eq!(parsed.metadata.version_major, 1);
    assert_eq!(parsed.metadata.version_minor, 1);
    assert_eq!(parsed.metadata.mode, 0);
    assert_eq!(parsed.metadata.vector_length, 0);
    // Default ABI version is 1 for the first release. Parser carries the value as-is.
    assert_eq!(
        parsed.metadata.abi_version,
        ProgramMetadata::default().abi_version
    );
}
#[test]
fn parse_rejects_unknown_mode_bits() {
    let bytes = encode_with(ProgramMetadata::default(), |m| {
        m.mode = 0x80; // unknown bit
    });
    let err = ProgramMetadata::parse(&bytes).unwrap_err();
    assert_eq!(err, VMError::UnsupportedProgramFeatureBits { bits: 0x80 });
}
#[test]
fn parse_rejects_retired_transactional_memory_bit() {
    let bytes = encode_with(ProgramMetadata::default(), |metadata| {
        metadata.mode = 0x04;
    });
    assert_eq!(
        ProgramMetadata::parse(&bytes).unwrap_err(),
        VMError::UnsupportedProgramFeatureBits { bits: 0x04 }
    );
}
#[test]
fn parse_rejects_retired_minor_zero_without_cntr() {
    let bytes = encode_with(ProgramMetadata::default(), |m| {
        m.version_minor = 0;
    });
    let current_abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    assert_eq!(&bytes[17..49], current_abi_hash.as_slice());
    assert_eq!(
        ProgramMetadata::parse(&bytes).unwrap_err(),
        VMError::UnsupportedProgramVersion { major: 1, minor: 0 },
    );
}
#[test]
fn parse_rejects_retired_pointer_layout_abi_hash_at_current_header() {
    // The retired pointer table assigned Amount=0x0010 and Quantity=0x0013.
    // Its descriptor must not become valid under the current header.
    const PRE_RESET_ABI_HASH_HEX: &str =
        "98679112b5a065a4dc962c5cfe128d0c545ed948f915ea8804767d369e4ef64f";
    let mut bytes = ProgramMetadata::default_for(1, 1, 1).encode();
    let expected = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    let pre_reset = hex::decode(PRE_RESET_ABI_HASH_HEX).expect("valid pre-reset ABI hash vector");
    bytes[17..49].copy_from_slice(&pre_reset);
    let actual: [u8; 32] = bytes[17..49].try_into().expect("fixed ABI hash field");
    assert!(matches!(
        ProgramMetadata::parse(&bytes),
        Err(VMError::ArtifactAbiHashMismatch {
            expected: observed_expected,
            actual: observed_actual,
        }) if observed_expected == expected && observed_actual == actual
    ));
}
#[test]
fn parse_accepts_vector_len_without_vector_flag() {
    // Vector length may be present even if VECTOR bit is off.
    let bytes = encode_with(ProgramMetadata::default(), |m| {
        m.mode = 0; // VECTOR not set
        m.vector_length = 8;
    });
    let parsed = ProgramMetadata::parse(&bytes).expect("parse ok without VECTOR flag");
    assert_eq!(parsed.metadata.mode & ivm_mode::VECTOR, 0);
    assert_eq!(parsed.metadata.vector_length, 8);
}
#[test]
fn parse_accepts_vector_len_with_flag() {
    let bytes = encode_with(ProgramMetadata::default(), |m| {
        m.mode = ivm_mode::VECTOR;
        m.vector_length = 8;
    });
    let parsed = ProgramMetadata::parse(&bytes).expect("parse vector header");
    assert_eq!(parsed.metadata.mode & ivm_mode::VECTOR, ivm_mode::VECTOR);
    assert_eq!(parsed.metadata.vector_length, 8);
}
#[test]
fn parse_rejects_vector_len_above_abi_max() {
    let bytes = encode_with(ProgramMetadata::default(), |m| {
        m.mode = ivm_mode::VECTOR;
        m.vector_length = ivm::VECTOR_LENGTH_MAX + 1;
    });
    let err = ProgramMetadata::parse(&bytes).unwrap_err();
    assert_eq!(
        err,
        VMError::ProgramVectorLengthTooLarge {
            vector_length: ivm::VECTOR_LENGTH_MAX + 1,
            max_allowed: ivm::VECTOR_LENGTH_MAX,
        }
    );
}
#[test]
fn parse_rejects_wrong_major_version() {
    let bytes = encode_with(ProgramMetadata::default(), |m| {
        m.version_major = 0;
    });
    let err = ProgramMetadata::parse(&bytes).unwrap_err();
    assert_eq!(
        err,
        VMError::UnsupportedProgramVersion { major: 0, minor: 1 }
    );
    let bytes = encode_with(ProgramMetadata::default(), |m| {
        m.version_major = 2;
    });
    let err = ProgramMetadata::parse(&bytes).unwrap_err();
    assert_eq!(
        err,
        VMError::UnsupportedProgramVersion { major: 2, minor: 1 }
    );
}
#[test]
fn parse_accepts_contract_minor_one_with_cntr() {
    let bytes = minimal_contract_artifact();
    let parsed = ProgramMetadata::parse(&bytes).expect("parse contract artifact");
    assert_eq!(parsed.metadata.version_minor, 1);
    assert!(
        parsed.contract_interface.is_some(),
        "CNTR section must decode"
    );
    assert!(
        parsed.code_offset > parsed.header_len,
        "CNTR prefix must advance code offset"
    );
}
#[test]
fn parse_accepts_contract_debug_section() {
    let bytes = minimal_contract_artifact_with_debug();
    let parsed = ProgramMetadata::parse(&bytes).expect("parse contract artifact with debug");
    let debug = parsed.contract_debug.expect("DBG1 section must decode");
    assert_eq!(debug.source_map.len(), 1);
    assert_eq!(debug.source_map[0].function_name, "main");
    assert_eq!(
        debug.source_map[0].source.source_path.as_deref(),
        Some("contracts/demo.ko")
    );
    assert_eq!(debug.source_map[0].source.line, 2);
    assert_eq!(debug.budget_report.len(), 1);
    assert_eq!(debug.budget_report[0].frame_bytes, 0);
    assert_eq!(
        debug.budget_report[0]
            .source
            .as_ref()
            .and_then(|source| source.source_path.as_deref()),
        Some("contracts/demo.ko")
    );
}
#[test]
fn parse_accepts_generic_minor_one_without_cntr() {
    let mut bytes = ProgramMetadata::default().encode();
    bytes.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let parsed = ProgramMetadata::parse(&bytes).expect("generic 1.1 artifact must parse");
    assert!(parsed.contract_interface.is_none());
    assert_eq!(parsed.code_offset, parsed.header_len);
}
#[test]
fn parse_rejects_unknown_minor_version() {
    let bytes = encode_with(ProgramMetadata::default(), |m| {
        m.version_minor = 2;
    });
    let err = ProgramMetadata::parse(&bytes).unwrap_err();
    assert_eq!(
        err,
        VMError::UnsupportedProgramVersion { major: 1, minor: 2 }
    );
}
#[test]
fn load_program_honors_zk_mode_bit() {
    let mut bytes = ProgramMetadata {
        mode: ivm_mode::ZK,
        abi_version: 1,
        ..ProgramMetadata::default()
    }
    .encode();
    bytes.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let mut vm = ivm::IVM::new(u64::MAX);
    assert!(!vm.zk_mode_enabled());
    vm.load_program(&bytes).expect("load zk program");
    assert!(vm.zk_mode_enabled());
}
