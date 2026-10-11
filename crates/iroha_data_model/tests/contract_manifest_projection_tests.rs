//! Native wire and allocator observations for borrowed manifest projections.

use super::{FAIL_SIZE, empty_manifest, measured, owned_context, populated_manifest};
use iroha_data_model::smart_contract::{
    entrypoint::{
        EntrypointValueKindV1 as Kind, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
        MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH,
    },
    manifest::{
        BorrowedEntrypoints, BorrowedStates, ContractManifest, ContractManifestSignaturePayload,
        ContractManifestSignaturePayloadView, EntrypointDescriptorView,
        ManifestEntrypointSequenceV1, ManifestStateSequenceV1, ManifestStateTypeNameV1,
        ManifestStateTypeNodeV1 as Node, ManifestStateTypeV1, ManifestTypeNameView,
        StateDescriptor, StateDescriptorView,
    },
};
use norito::core::{BoundedEncodeError, Error, SerializePayload};
use std::io::{self, Write};

fn owned_payload(manifest: ContractManifest) -> ContractManifestSignaturePayload {
    let ContractManifest {
        seiyaku_name,
        code_hash,
        abi_hash,
        compiler_fingerprint,
        features_bitmap,
        access_set_hints,
        entrypoints,
        states,
        error_types,
        error_messages,
        kotoba,
        provenance: _,
    } = manifest;
    ContractManifestSignaturePayload {
        seiyaku_name,
        code_hash,
        abi_hash,
        compiler_fingerprint,
        features_bitmap,
        access_set_hints,
        entrypoints,
        states,
        error_types,
        error_messages,
        kotoba,
    }
}

#[test]
fn signing_view_preserves_original_native_frame_and_optional_empty_semantics() {
    for fixture in [populated_manifest(), empty_manifest(), {
        let mut manifest = empty_manifest();
        manifest.seiyaku_name = Some(String::new());
        manifest.compiler_fingerprint = Some(String::new());
        manifest.entrypoints = Some(Vec::new());
        manifest.states = Some(Vec::new());
        manifest.error_types = Some(Vec::new());
        manifest.error_messages = Some(Vec::new());
        manifest.kotoba = Some(Vec::new());
        manifest
    }] {
        let expected = owned_payload(fixture.clone());
        let wire = norito::encode_canonical(&expected).unwrap();
        let (_owner, _grant, context) = owned_context(wire.len());
        let view = fixture.signature_payload();
        assert_eq!(
            std::mem::align_of_val(&view),
            std::mem::align_of::<ContractManifestSignaturePayload>()
        );
        assert_eq!(view.to_bytes(&context, wire.len()).unwrap(), wire);
        let decoded = norito::decode_canonical::<ContractManifestSignaturePayload>(&wire).unwrap();
        assert_eq!(decoded, expected);
        let json = norito::json::to_json(&decoded).unwrap();
        assert_eq!(
            norito::json::from_str::<ContractManifestSignaturePayload>(&json).unwrap(),
            expected
        );
    }
    let absent = norito::encode_canonical(&empty_manifest().signature_payload()).unwrap();
    let mut present = empty_manifest();
    present.states = Some(Vec::new());
    assert_ne!(
        absent,
        norito::encode_canonical(&present.signature_payload()).unwrap()
    );
}

#[test]
fn signature_output_has_one_exact_native_allocation_and_cumulative_refusal() {
    let manifest = populated_manifest();
    let expected = norito::encode_canonical(&owned_payload(manifest.clone())).unwrap();
    let (_owner, _grant, context) = owned_context(expected.len());
    norito::canonical_frame_len(&manifest.signature_payload()).unwrap();
    let (output, allocations) =
        measured(|| manifest.signature_payload_bytes(&context, expected.len()));
    let output = output.unwrap();
    assert_eq!(output, expected);
    assert_eq!(output.capacity(), expected.len());
    assert_eq!(
        allocations, 1,
        "only the original exact output allocation is permitted"
    );
    assert_eq!(context.consumed_allocated_bytes(), expected.len() as u64);
    let (error, allocations) =
        measured(|| manifest.signature_payload_bytes(&context, expected.len()));
    assert!(
        matches!(error, Err(BoundedEncodeError::Serialization(ref error)) if error.is_decode_resource_limit())
    );
    assert_eq!(
        allocations, 0,
        "the same cumulative owner refuses a second output before allocation"
    );
    assert_eq!(context.consumed_allocated_bytes(), expected.len() as u64);
}

#[test]
fn canonical_signature_writer_needs_no_frame_buffer_and_refuses_before_writing() {
    let manifest = populated_manifest();
    let expected = norito::encode_canonical(&owned_payload(manifest.clone())).unwrap();
    let (_owner, _grant, context) = owned_context(0);
    let mut writer = CountWriter::default();
    let (result, allocations) = measured(|| {
        manifest
            .signature_payload()
            .write_canonical(&context, expected.len(), &mut writer)
    });
    result.unwrap();
    assert_eq!(writer.0, expected.len());
    assert_eq!(allocations, 0);
    assert_eq!(context.consumed_allocated_bytes(), 0);
    let mut destination = vec![0; expected.len()];
    let mut exact = io::Cursor::new(destination.as_mut_slice());
    manifest
        .signature_payload()
        .write_canonical(&context, expected.len(), &mut exact)
        .unwrap();
    assert_eq!(exact.position() as usize, expected.len());
    assert_eq!(destination, expected);
    let mut untouched = CountWriter::default();
    let (result, allocations) = measured(|| {
        manifest
            .signature_payload()
            .write_canonical(&context, expected.len() - 1, &mut untouched)
    });
    assert!(matches!(
        result,
        Err(BoundedEncodeError::FrameTooLarge { .. })
    ));
    assert_eq!(untouched.0, 0);
    assert_eq!(allocations, 0);
}

#[test]
fn frame_limit_and_actual_allocator_refusals_preserve_native_error() {
    let manifest = populated_manifest();
    let exact = norito::canonical_frame_len(&manifest.signature_payload()).unwrap();
    let (_owner, _grant, context) = owned_context(exact);
    let (error, allocations) = measured(|| manifest.signature_payload_bytes(&context, exact - 1));
    assert!(
        matches!(error, Err(BoundedEncodeError::FrameTooLarge { encoded_bytes, max_bytes }) if encoded_bytes == exact && max_bytes == exact - 1)
    );
    assert_eq!(allocations, 0);
    assert_eq!(context.consumed_allocated_bytes(), 0);
    FAIL_SIZE.with(|size| size.set(Some(exact)));
    let (error, allocations) = measured(|| manifest.signature_payload_bytes(&context, exact));
    assert!(matches!(error, Err(BoundedEncodeError::AllocationFailed { bytes }) if bytes == exact));
    assert_eq!(allocations, 1);
}

#[test]
fn signing_refusal_retains_the_native_encoding_domain() {
    let manifest = populated_manifest();
    let key = iroha_crypto::KeyPair::try_random().unwrap();
    let exact = norito::canonical_frame_len(&manifest.signature_payload()).unwrap();
    let (_owner, _grant, context) = owned_context(0);
    let (result, allocations) = measured(|| manifest.try_signed(&context, exact, &key));
    assert!(matches!(result,
        Err(iroha_data_model::smart_contract::manifest::ManifestSigningError::Encoding(
            BoundedEncodeError::Serialization(ref error))) if error.is_decode_resource_limit()));
    assert_eq!(allocations, 0);
}

#[test]
fn canonical_signing_ignores_ambient_layout_and_descriptor_views_borrow_children() {
    let manifest = populated_manifest();
    let expected = norito::encode_canonical(&owned_payload(manifest.clone())).unwrap();
    let (_owner, _grant, context) = owned_context(expected.len());
    let flags = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _alternate = norito::core::DecodeFlagsGuard::enter(flags);
    assert_eq!(
        manifest
            .signature_payload_bytes(&context, expected.len())
            .unwrap(),
        expected
    );
    let original = &manifest.entrypoints.as_ref().unwrap()[0];
    let (view, allocations) = measured(|| EntrypointDescriptorView::from(original));
    assert_eq!(allocations, 0);
    assert!(std::ptr::eq(view.name.as_ptr(), original.name.as_ptr()));
    assert!(std::ptr::eq(view.params.0, &original.params));
    assert!(std::ptr::eq(
        view.argument_schema.0,
        &original.argument_schema
    ));
    assert!(std::ptr::eq(view.triggers.0, &original.triggers));
    let (same, allocations) = measured(|| view.same_content(original));
    assert!(same);
    assert_eq!(allocations, 0);
}

struct ShortEntries;
impl ManifestEntrypointSequenceV1 for ShortEntries {
    fn len(&self) -> usize {
        1
    }
    fn get(&self, _: usize) -> Option<EntrypointDescriptorView<'_>> {
        None
    }
}
#[test]
fn inconsistent_projected_sequence_refuses_before_output_allocation() {
    let source = empty_manifest();
    let mut view = source.signature_payload();
    view.entrypoints = Some(BorrowedEntrypoints(&ShortEntries));
    let (_owner, _grant, context) = owned_context(1024);
    let (error, allocations) = measured(|| view.to_bytes(&context, 1024));
    assert!(matches!(
        error,
        Err(BoundedEncodeError::Serialization(Error::LengthMismatch))
    ));
    assert_eq!(allocations, 0);
}

enum NativeType {
    Unit,
    Error(String),
    Scalar(Kind),
    Tuple(Vec<Self>),
    Struct(String, Vec<(String, Self)>),
    StateMap(Box<Self>, Box<Self>),
    Option(Box<Self>),
    Result(Box<Self>, Box<Self>),
    List(Box<Self>, u8),
    Cursor(Kind),
}
impl ManifestStateTypeV1 for NativeType {
    fn node(&self) -> Node<'_> {
        match self {
            Self::Unit => Node::Unit,
            Self::Error(name) => Node::Error(name),
            Self::Scalar(kind) => Node::Scalar(*kind),
            Self::Tuple(items) => Node::Tuple(items.len()),
            Self::Struct(name, fields) => Node::Struct {
                name,
                fields: fields.len(),
            },
            Self::StateMap(_, _) => Node::StateMap,
            Self::Option(_) => Node::Option,
            Self::Result(_, _) => Node::Result,
            Self::List(_, cap) => Node::List(*cap),
            Self::Cursor(key) => Node::StateCursor(*key),
        }
    }
    fn child(&self, index: usize) -> Option<&dyn ManifestStateTypeV1> {
        let child = match self {
            Self::Tuple(items) => items.get(index),
            Self::Struct(_, fields) => fields.get(index).map(|(_, ty)| ty),
            Self::StateMap(key, value) | Self::Result(key, value) => match index {
                0 => Some(key.as_ref()),
                1 => Some(value.as_ref()),
                _ => None,
            },
            Self::Option(value) | Self::List(value, _) => (index == 0).then_some(value.as_ref()),
            _ => None,
        };
        child.map(|ty| -> &dyn ManifestStateTypeV1 { ty })
    }
    fn field_name(&self, index: usize) -> Option<&str> {
        match self {
            Self::Struct(_, fields) => fields.get(index).map(|(name, _)| name.as_str()),
            _ => None,
        }
    }
}

#[derive(Default)]
struct CountWriter(usize);
impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn native_state_spelling_preserves_all_shapes_and_uses_one_charged_string() {
    let fixtures = [
        (NativeType::Unit, "()"),
        (NativeType::Error("PaymentError".into()), "PaymentError"),
        (
            NativeType::Tuple(vec![
                NativeType::Scalar(Kind::Int),
                NativeType::Scalar(Kind::Bool),
            ]),
            "(int, bool)",
        ),
        (
            NativeType::Struct(
                "Record".into(),
                vec![("amount".into(), NativeType::Scalar(Kind::Quantity))],
            ),
            "Record{amount: quantity}",
        ),
        (
            NativeType::StateMap(
                Box::new(NativeType::Scalar(Kind::AccountId)),
                Box::new(NativeType::Scalar(Kind::Quantity)),
            ),
            "StateMap<AccountId, quantity>",
        ),
        (
            NativeType::Option(Box::new(NativeType::Scalar(Kind::String))),
            "Option<string>",
        ),
        (
            NativeType::Result(
                Box::new(NativeType::Scalar(Kind::Int)),
                Box::new(NativeType::Error("PaymentError".into())),
            ),
            "Result<int, PaymentError>",
        ),
        (
            NativeType::List(Box::new(NativeType::Scalar(Kind::Blob)), 255),
            "List<bytes, 255>",
        ),
        (
            NativeType::Cursor(Kind::DataSpaceId),
            "StateCursor<DataSpaceId>",
        ),
    ];
    for (source, expected) in fixtures {
        let view = ManifestStateTypeNameV1::new(&source);
        let mut writer = CountWriter::default();
        let ((len, same), allocations) = measured(|| {
            view.write_raw(&mut writer).unwrap();
            (view.byte_len().unwrap(), view.same_text(expected).unwrap())
        });
        assert!(same);
        assert_eq!(len, expected.len());
        assert_eq!(writer.0, len);
        assert_eq!(allocations, 0);
        let (_owner, _grant, context) = owned_context(len);
        let (materialized, allocations) = measured(|| view.materialize(&context));
        let materialized = materialized.unwrap();
        assert_eq!(materialized, expected);
        assert_eq!(materialized.capacity(), len);
        assert_eq!(allocations, 1);
        assert_eq!(context.consumed_allocated_bytes(), len as u64);
        let (error, allocations) = measured(|| view.materialize(&context));
        assert!(error.unwrap_err().is_decode_resource_limit());
        assert_eq!(allocations, 0);
    }
}

#[test]
fn cursor_projection_uses_the_same_native_supported_kind_rule_without_schema_allocation() {
    for kind in [
        Kind::Int,
        Kind::Decimal,
        Kind::Quantity,
        Kind::Bool,
        Kind::String,
        Kind::Json,
        Kind::Name,
        Kind::AccountId,
        Kind::AssetDefinitionId,
        Kind::AssetId,
        Kind::DomainId,
        Kind::NftId,
        Kind::DataSpaceId,
        Kind::Blob,
    ] {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::StateCursor(kind)],
        };
        assert_eq!(kind.is_state_cursor_key(), schema.validate());
        let source = NativeType::Cursor(kind);
        let view = ManifestStateTypeNameV1::new(&source);
        let (length, allocations) = measured(|| view.byte_len());
        assert_eq!(allocations, 0);
        if kind == Kind::Json {
            assert!(matches!(length, Err(Error::NonCanonicalEncoding)));
        } else {
            let expected = schema.canonical_type_name().unwrap();
            assert_eq!(length.unwrap(), expected.len());
            assert!(view.same_text(&expected).unwrap());
        }
    }
}

#[test]
fn state_materialization_preserves_actual_allocator_refusal() {
    let source = NativeType::Option(Box::new(NativeType::Scalar(Kind::AccountId)));
    let view = ManifestStateTypeNameV1::new(&source);
    let length = view.byte_len().unwrap();
    let (_owner, _grant, context) = owned_context(length);
    FAIL_SIZE.with(|size| size.set(Some(length)));
    let (result, allocations) = measured(|| view.materialize(&context));
    assert!(matches!(result, Err(Error::AllocationFailed { bytes }) if bytes == length as u64));
    assert_eq!(allocations, 1);
    assert_eq!(context.consumed_allocated_bytes(), length as u64);
}

#[test]
fn wide_and_max_depth_types_use_no_heap_continuation_or_sibling_vector() {
    let wide = NativeType::Tuple((0..10_000).map(|_| NativeType::Scalar(Kind::Int)).collect());
    let mut writer = CountWriter::default();
    let (result, allocations) =
        measured(|| ManifestStateTypeNameV1::new(&wide).write_raw(&mut writer));
    result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(writer.0, 50_000);
    let mut deep = NativeType::Scalar(Kind::Int);
    for _ in 1..MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH {
        deep = NativeType::Option(Box::new(deep));
    }
    let (length, allocations) = measured(|| ManifestStateTypeNameV1::new(&deep).byte_len());
    assert_eq!(
        length.unwrap(),
        3 + (MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1) * 8
    );
    assert_eq!(allocations, 0);
    let too_deep = NativeType::Option(Box::new(deep));
    let (error, allocations) = measured(|| ManifestStateTypeNameV1::new(&too_deep).byte_len());
    assert!(matches!(error, Err(Error::LengthMismatch)));
    assert_eq!(allocations, 0);
}

struct ProjectedStates {
    source: NativeType,
}
impl ManifestStateSequenceV1 for ProjectedStates {
    fn len(&self) -> usize {
        1
    }
    fn get(&self, index: usize) -> Option<StateDescriptorView<'_>> {
        (index == 0).then_some(StateDescriptorView {
            name: "balance",
            type_name: ManifestTypeNameView::State(ManifestStateTypeNameV1::new(&self.source)),
        })
    }
}
#[test]
fn projected_state_rows_match_the_existing_native_string_and_sequence_codecs() {
    let projected = ProjectedStates {
        source: NativeType::StateMap(
            Box::new(NativeType::Scalar(Kind::AccountId)),
            Box::new(NativeType::Scalar(Kind::Quantity)),
        ),
    };
    let mut manifest = empty_manifest();
    manifest.states = Some(vec![StateDescriptor {
        name: "balance".into(),
        type_name: "StateMap<AccountId, quantity>".into(),
    }]);
    let expected = norito::encode_canonical(&owned_payload(manifest.clone())).unwrap();
    let mut view: ContractManifestSignaturePayloadView<'_> = manifest.signature_payload();
    view.states = Some(BorrowedStates(&projected));
    let (_owner, _grant, context) = owned_context(expected.len());
    let (wire, allocations) = measured(|| view.to_bytes(&context, expected.len()));
    assert_eq!(wire.unwrap(), expected);
    assert_eq!(allocations, 1);
    let (same, allocations) = measured(|| {
        projected
            .get(0)
            .unwrap()
            .same_content(&manifest.states.as_ref().unwrap()[0])
    });
    assert!(same.unwrap());
    assert_eq!(allocations, 0);
    let mut destination = Vec::new();
    ManifestStateTypeNameV1::new(&projected.source)
        .serialize(&mut norito::core::Encoder::for_buffer(&mut destination))
        .unwrap();
    let mut original = Vec::new();
    manifest.states.as_ref().unwrap()[0]
        .type_name
        .serialize(&mut norito::core::Encoder::for_buffer(&mut original))
        .unwrap();
    assert_eq!(destination, original);
}

#[path = "contract_manifest_instruction_registry_projection_tests.rs"]
mod instruction_registry_projection_tests;
