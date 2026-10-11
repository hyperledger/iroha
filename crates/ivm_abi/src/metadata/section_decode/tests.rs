//! Encoded CNTR/DBG1 retry and deterministic rejection at the metadata boundary.

use super::*;
use crate::metadata::*;
use norito::core::with_decode_limits_scope;

fn allocation_limit(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

fn interface() -> EmbeddedContractInterfaceV1 {
    EmbeddedContractInterfaceV1 {
        permissions: Vec::new(),
        events: Vec::new(),
        callables: Vec::new(),
        seiyaku_name: "DecodeRetry".to_owned(),
        compiler_fingerprint: "section-decode-tests".to_owned(),
        abi_hash: crate::syscalls::compute_abi_hash(crate::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: Vec::new(),
        states: vec![EmbeddedStateDescriptor {
            name: "enabled".to_owned(),
            ty: EmbeddedStateType::Bool,
        }],
        error_messages: Vec::new(),
        enum_types: Vec::new(),
        error_types: Vec::new(),
    }
}

fn debug() -> EmbeddedContractDebugInfoV1 {
    EmbeddedContractDebugInfoV1 {
        source_map: vec![EmbeddedSourceMapEntryV1 {
            function_name: "main".to_owned(),
            pc_start: 0,
            pc_end: 4,
            source: EmbeddedSourceLocation {
                source_path: Some("decode_retry.ko".to_owned()),
                source_id: 1,
                byte_start: 0,
                byte_end: 10,
                line: 1,
                column: 1,
            },
        }],
        budget_report: Vec::new(),
    }
}

#[test]
fn encoded_sections_preserve_enclosing_refusal_then_retry_identically() {
    let interface = interface();
    let debug = debug();
    let contract_bytes = interface.encode_section();
    let debug_bytes = debug.encode_section();
    let expected = VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity);
    for limit in [
        allocation_limit(0),
        DecodeLimits::new(0, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
        DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX),
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
    ] {
        assert_eq!(
            with_decode_limits_scope(limit, || {
                parse_contract_interface_section(&contract_bytes, 0)
            })
            .unwrap_err(),
            expected
        );
        assert_eq!(
            with_decode_limits_scope(limit, || { parse_contract_debug_section(&debug_bytes, 0) })
                .unwrap_err(),
            expected
        );
    }
    assert_eq!(
        parse_contract_interface_section(&contract_bytes, 0).unwrap(),
        (interface, contract_bytes.len())
    );
    assert_eq!(
        parse_contract_debug_section(&debug_bytes, 0).unwrap(),
        (debug, debug_bytes.len())
    );
}

#[test]
fn canonical_protocol_refusal_remains_invalid_with_equal_enclosing_limit() {
    let bytes = norito::encode_canonical(&vec!["canonical".to_owned()]).unwrap();
    let protocol = allocation_limit(0);
    assert_eq!(
        decode::<Vec<String>>(&bytes, protocol).unwrap_err(),
        VMError::InvalidMetadata
    );
    assert_eq!(
        with_decode_limits_scope(protocol, || decode::<Vec<String>>(&bytes, protocol)).unwrap_err(),
        VMError::InvalidMetadata
    );
    assert_eq!(
        decode::<Vec<String>>(&bytes, allocation_limit(usize::MAX)).unwrap(),
        vec!["canonical".to_owned()]
    );
}

fn assert_malformed<T: std::fmt::Debug>(
    section: Vec<u8>,
    parser: impl Fn(&[u8], usize) -> Result<T, VMError>,
) {
    for malformed in [
        section[..7].to_vec(),
        section[..section.len() - 1].to_vec(),
        {
            let mut bad = section;
            bad[8] ^= 0xff;
            bad
        },
    ] {
        assert_eq!(
            with_decode_limits_scope(allocation_limit(0), || parser(&malformed, 0)).unwrap_err(),
            VMError::InvalidMetadata,
        );
    }
}

#[test]
fn malformed_section_frames_remain_invalid_under_local_pressure() {
    assert_malformed(
        interface().encode_section(),
        parse_contract_interface_section,
    );
    assert_malformed(debug().encode_section(), parse_contract_debug_section);
}

#[test]
fn whole_artifact_image_limit_precedes_section_resource_admission() {
    let mut bytes = ProgramMetadata::default().encode();
    bytes.extend_from_slice(&interface().encode_section());
    bytes.resize(HEADER_SIZE + MAX_PROGRAM_IMAGE_BYTES_V1 + 1, 0);
    assert_eq!(
        with_decode_limits_scope(allocation_limit(0), || ProgramMetadata::parse(&bytes))
            .unwrap_err(),
        VMError::InvalidMetadata
    );
    assert_eq!(
        ProgramMetadata::parse(&bytes).unwrap_err(),
        VMError::InvalidMetadata
    );
}

#[test]
fn trigger_json_metadata_preserves_each_cumulative_refusal_then_retries() {
    use iroha_data_model::{
        events::{
            EventFilterBox,
            time::{ExecutionTime, TimeEventFilter},
        },
        smart_contract::manifest::TriggerCallback,
        trigger::action::Repeats,
    };
    use iroha_model_base::metadata::Metadata;

    let mut metadata = Metadata::default();
    metadata.insert(
        "payload".parse().unwrap(),
        norito::json!([1, 2, "canonical"]),
    );
    let mut original = interface();
    original.entrypoints.push(EmbeddedEntrypointDescriptor {
        name: "run".to_owned(),
        kind: EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: None,
        return_schema: None,
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: vec![TriggerDescriptor {
            id: "wake".parse().unwrap(),
            repeats: Repeats::Indefinitely,
            filter: EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
            authority: None,
            metadata,
            callback: TriggerCallback {
                namespace: None,
                entrypoint: "run".to_owned(),
            },
        }],
        entry_pc: 0,
    });
    let bytes = original.encode_section();
    let payload = &bytes[CONTRACT_INTERFACE_SECTION_HEADER_SIZE..];
    let mut limit = 0;
    loop {
        let outcome = with_decode_limits_scope(allocation_limit(limit), || {
            norito::decode_canonical_for_admission::<EmbeddedContractInterfaceV1>(
                payload,
                CONTRACT_INTERFACE_DECODE_LIMITS_V1,
            )
        });
        match outcome {
            Ok(decoded) => {
                assert_eq!(decoded, original);
                break;
            }
            Err(error) => {
                assert_eq!(
                    error.kind(),
                    norito::core::DecodeAttemptErrorKind::EnclosingLimit,
                    "trigger metadata at budget {limit}: {error}"
                );
                assert_eq!(
                    with_decode_limits_scope(allocation_limit(limit), || {
                        parse_contract_interface_section(&bytes, 0)
                    })
                    .unwrap_err(),
                    VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity)
                );
                let Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted,
                    ..
                }) = error.into_error().decode_resource_error()
                else {
                    panic!("expected original cumulative refusal");
                };
                let next = usize::try_from(attempted).unwrap();
                assert!(next > limit && next < CONTRACT_INTERFACE_MAX_DECODE_ALLOCATION_BYTES_V1);
                limit = next;
            }
        }
    }
    assert_eq!(
        parse_contract_interface_section(&bytes, 0).unwrap(),
        (original, bytes.len())
    );
}
