use super::*;
fn compact(tokens: TokenStream2) -> String {
    tokens
        .to_string()
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect()
}
/// Codegen tokens that belong only to the retired packed layouts.
const RETIRED_LAYOUT_TOKENS: [&str; 17] = [
    "use_packed_struct",
    "use_field_bitset",
    "decode_context_packed_",
    "decode_context_field_prefix",
    "decode_context_field_fixed_canonical",
    "decode_context_byte_array",
    "PackedField",
    "write_packed_fields",
    "mark_field_bitset_used_if_encoding",
    "SequentialOverrideGuard",
    "eprintln!",
    "__norito_packed",
    "__offs",
    "__sizes",
    "__bitset",
    "__packed_data_len",
    "__expected_bitset",
];
#[test]
fn context_field_paths_delegate_copy_and_context_setup_to_core() {
    let struct_input: DeriveInput = syn::parse_quote! {
        struct Record {
            opaque: Opaque,
        }
    };
    let Data::Struct(struct_data) = &struct_input.data else {
        unreachable!("test input is a struct");
    };
    let struct_expansion = compact(derive_struct_deserialize(
        &struct_input.ident,
        &struct_input.generics,
        &struct_data.fields,
        &struct_input.attrs,
    ));
    let tuple_input: DeriveInput = syn::parse_quote! {
        struct Tuple(Opaque);
    };
    let Data::Struct(tuple_data) = &tuple_input.data else {
        unreachable!("test input is a struct");
    };
    let tuple_expansion = compact(derive_struct_deserialize(
        &tuple_input.ident,
        &tuple_input.generics,
        &tuple_data.fields,
        &tuple_input.attrs,
    ));
    let enum_input: DeriveInput = syn::parse_quote! {
        enum Message {
            Tuple(Opaque, u64),
            Named { values: Vec<u32> },
        }
    };
    let Data::Enum(enum_data) = &enum_input.data else {
        unreachable!("test input is an enum");
    };
    let enum_expansion = compact(derive_enum_deserialize(
        &enum_input.ident,
        &enum_input.generics,
        enum_data,
        &enum_input.attrs,
    ));
    for expansion in [&struct_expansion, &tuple_expansion, &enum_expansion] {
        assert!(
            expansion
                .contains("norito::core::decode_context_field_canonical::<Opaque>(ptr,&mutoffset)"),
            "framed fields must use the shared canonical context-field helper"
        );
        assert!(
            expansion.contains("finish_context_fields(ptr,offset)"),
            "full-consumption validation must remain shared"
        );
        assert!(
            !expansion.contains("std::alloc::alloc("),
            "generated decoder must not inline archived-field allocation"
        );
        assert!(
            !expansion.contains("PayloadCtxGuard::enter(tmp_slice)"),
            "generated decoder must not inline archived-field context setup"
        );
        for retired_helper in [
            "decode_context_field_canonical_or_archived",
            "decode_context_field_archived::<",
            "decode_context_field_archived_compat",
            "decode_context_field_fixed_archived",
            "payload_slice_from_ptr(ptr)",
            "read_len_dyn_slice",
            "try_read_len_ptr_unchecked",
            "__fallback",
        ] {
            assert!(
                !expansion.contains(retired_helper),
                "generated decoders must not retry retired field encodings via {retired_helper}"
            );
        }
        for retired in RETIRED_LAYOUT_TOKENS {
            assert!(
                !expansion.contains(retired),
                "generated decoders must not carry packed-layout code: {retired}"
            );
        }
    }
    assert!(
        enum_expansion.contains("decode_context_field_canonical::<u64>(ptr,&mutoffset)"),
        "fixed-size enum fields keep their length-prefixed frame"
    );
    assert!(
        enum_expansion.contains("decode_context_field_canonical::<Vec<u32>>(ptr,&mutoffset)"),
        "self-delimiting enum fields keep their length-prefixed frame"
    );
    assert!(
        !enum_expansion.contains("decode_context_field_flexible"),
        "enum fields must not consume bytes beyond their declared frame"
    );
    assert!(
        enum_expansion.contains("payload_range_from_ptr(ptr,4)"),
        "enum tags must use the bounded payload helper"
    );
    assert!(
        struct_expansion.contains(
            "ifnorito::debug_trace_enabled(){norito::trace_struct_decode(stringify!(Record),ptr);}"
        ),
        "the named-struct trace must stay behind the debug toggle in the cold norito helper"
    );
}
#[test]
fn binary_codegen_emits_only_the_length_prefixed_layout() {
    let inputs: [DeriveInput; 3] = [
        syn::parse_quote! {
            struct Named {
                #[norito(flatten)]
                inner: Inner,
                raw: [u8; 32],
                maybe: Option<u64>,
                values: Vec<u32>,
                #[norito(skip)]
                cache: Cache,
            }
        },
        syn::parse_quote! { struct Tuple(Payload, [u8; 8], u16); },
        syn::parse_quote! {
            enum Message {
                Unit,
                Tuple(Payload, [u8; 8], u16),
                Named { raw: [u8; 32], values: Vec<u32> },
            }
        },
    ];
    for input in inputs {
        let (serialize, deserialize) = match &input.data {
            Data::Struct(data) => (
                derive_struct_serialize(
                    &input.ident,
                    &input.generics,
                    &data.fields,
                    &input.attrs,
                    true,
                ),
                derive_struct_deserialize(
                    &input.ident,
                    &input.generics,
                    &data.fields,
                    &input.attrs,
                ),
            ),
            Data::Enum(data) => (
                derive_enum_serialize(&input.ident, &input.generics, data, &input.attrs, true),
                derive_enum_deserialize(&input.ident, &input.generics, data, &input.attrs),
            ),
            Data::Union(_) => unreachable!("test inputs are structs or enums"),
        };
        let serialize = compact(serialize);
        assert!(
            serialize.contains("norito::core::write_len_prefixed(writer,"),
            "{name} fields must stream into length-prefixed frames",
            name = input.ident,
        );
        for expansion in [serialize, compact(deserialize)] {
            for retired in RETIRED_LAYOUT_TOKENS {
                assert!(
                    !expansion.contains(retired),
                    "{name} expansion must not carry packed-layout code: {retired}",
                    name = input.ident,
                );
            }
        }
    }
}
#[test]
fn binary_default_attributes_do_not_generate_missing_field_fallbacks() {
    let struct_input: DeriveInput = syn::parse_quote! {
        struct Record {
            #[norito(default)]
            count: u32,
            #[norito(default = "custom_default")]
            marker: u64,
        }
    };
    let Data::Struct(struct_data) = &struct_input.data else {
        unreachable!("test input is a struct");
    };
    let struct_expansion = compact(derive_struct_deserialize(
        &struct_input.ident,
        &struct_input.generics,
        &struct_data.fields,
        &struct_input.attrs,
    ));
    let enum_input: DeriveInput = syn::parse_quote! {
        enum Message {
            Values {
                #[norito(default)]
                count: u32,
                #[norito(default = "custom_default")]
                marker: u64,
            },
        }
    };
    let Data::Enum(enum_data) = &enum_input.data else {
        unreachable!("test input is an enum");
    };
    let enum_expansion = compact(derive_enum_deserialize(
        &enum_input.ident,
        &enum_input.generics,
        enum_data,
        &enum_input.attrs,
    ));
    for expansion in [&struct_expansion, &enum_expansion] {
        assert!(
            expansion.contains("decode_context_field_canonical::<"),
            "default-annotated binary fields must use the canonical decoder"
        );
        assert!(
            !expansion.contains("custom_default") && !expansion.contains("Default::default"),
            "binary deserializers must not synthesize omitted default-annotated fields"
        );
        assert!(
            !expansion.contains("Err(norito::core::Error::LengthMismatch)=>"),
            "binary length mismatches must remain terminal"
        );
    }
}
#[test]
fn ordinary_struct_fields_use_counted_length_streaming() {
    let input: DeriveInput = syn::parse_quote! {
        struct Envelope {
            named: Vec<u8>,
            other: String,
        }
    };
    let Data::Struct(data) = &input.data else {
        unreachable!();
    };
    let expansion = compact(derive_struct_serialize(
        &input.ident,
        &input.generics,
        &data.fields,
        &input.attrs,
        true,
    ));
    assert_eq!(expansion.matches("write_len_prefixed(").count(), 2);
    assert!(!expansion.contains("write_len_prefixed_exact("));
    assert!(expansion.contains("EncodeValueDepthGuard::enter()"));
}
#[test]
fn generated_serializers_use_two_argument_field_writers_without_scratch_buffers() {
    let inputs: [DeriveInput; 3] = [
        syn::parse_quote! {
            struct Named {
                payload: Opaque,
                bytes: [u8; 16],
                count: u64,
                note: String,
            }
        },
        syn::parse_quote! { struct Tuple(Opaque, [u8; 16], u64, String); },
        syn::parse_quote! {
            enum Message {
                Tuple(Opaque, [u8; 16], u64, String),
                Named { payload: Opaque, bytes: [u8; 16], count: u64, note: String },
            }
        },
    ];
    for input in inputs {
        let expansion = compact(match &input.data {
            Data::Struct(data) => derive_struct_serialize(
                &input.ident,
                &input.generics,
                &data.fields,
                &input.attrs,
                true,
            ),
            Data::Enum(data) => {
                derive_enum_serialize(&input.ident, &input.generics, data, &input.attrs, true)
            }
            Data::Union(_) => unreachable!("test inputs are structs or enums"),
        });
        assert!(expansion.contains("write_len_prefixed(writer,"));
        for forbidden in ["SmallBuf", "__norito_tmp", "__buf", "Vec::new()"] {
            assert!(
                !expansion.contains(forbidden),
                "{name} must not emit retired field scratch storage: {forbidden}",
                name = input.ident,
            );
        }
        for field_call in expansion.split("write_len_prefixed(").skip(1) {
            let arguments = field_call.split_once(')').expect("field call closes").0;
            assert_eq!(arguments.split(',').count(), 2, "{arguments}");
        }
    }
}
#[test]
fn ordinary_enum_fields_use_counted_length_streaming() {
    let input: DeriveInput = syn::parse_quote! {
        enum Envelope {
            Tuple(Vec<u8>),
            Named { payload: Vec<u8> },
        }
    };
    let Data::Enum(data) = &input.data else {
        unreachable!();
    };
    let expansion = compact(derive_enum_serialize(
        &input.ident,
        &input.generics,
        data,
        &input.attrs,
        true,
    ));
    assert!(expansion.matches("write_len_prefixed(").count() >= 2);
    assert!(!expansion.contains("write_len_prefixed_exact("));
    assert!(expansion.contains("EncodeValueDepthGuard::enter()"));
}
#[test]
fn enum_byte_array_lengths_use_the_raw_wire_width() {
    let input: DeriveInput = syn::parse_quote! {
        enum Envelope {
            Tuple([u8; 32]),
            Named { digest: [u8; 32] },
        }
    };
    let Data::Enum(data) = &input.data else {
        unreachable!();
    };
    let expansion = compact(derive_enum_serialize(
        &input.ident,
        &input.generics,
        data,
        &input.attrs,
        true,
    ));
    assert_eq!(
        expansion.matches("core::mem::size_of_val(field0)").count(),
        3,
        "tuple byte arrays must use their raw width in serialization and both length oracles"
    );
    assert_eq!(
        expansion.matches("core::mem::size_of_val(digest)").count(),
        3,
        "named byte arrays must use their raw width in serialization and both length oracles"
    );
    for incorrect in [
        "encoded_len_hint(field0)",
        "encoded_len_exact(field0)",
        "encoded_len_hint(digest)",
        "encoded_len_exact(digest)",
    ] {
        assert!(
            !expansion.contains(incorrect),
            "byte-array length oracle delegated to the generic array codec: {incorrect}"
        );
    }
}

#[test]
fn payload_and_frame_derives_share_reconstruction_without_identity_bounds() {
    for input in [
        syn::parse_quote! { struct Record<T> { value: T } },
        syn::parse_quote! { struct Record<T>(T); },
        syn::parse_quote! { struct Record; },
        syn::parse_quote! { enum Record<T> { Unit, Value(T), Named { value: T } } },
    ] {
        let input: DeriveInput = input;
        // Both public derive spellings call this same payload generator.
        let tokens = match &input.data {
            Data::Struct(data) => {
                derive_struct_deserialize(&input.ident, &input.generics, &data.fields, &input.attrs)
            }
            Data::Enum(data) => {
                derive_enum_deserialize(&input.ident, &input.generics, data, &input.attrs)
            }
            Data::Union(_) => unreachable!(),
        };
        let payload: syn::File = syn::parse2(tokens).expect("valid payload implementation");
        assert_eq!(payload.items.len(), 1);
        let payload_source = compact(quote!(#payload));
        assert!(payload_source.contains("norito::core::DeserializePayload"));
        // Debug labels may report Rust type names; they never select a frame.
        for forbidden in [
            "NoritoDeserialize",
            "NoritoSchema",
            "schema_hash",
            "IntoSchema",
            "module_path",
            "schema-structural",
        ] {
            assert!(
                !payload_source.contains(forbidden),
                "{forbidden}: {payload_source}"
            );
        }
        if !input.generics.params.is_empty() {
            assert!(payload_source.contains("T:for<'__d>norito::core::DeserializePayload<'__d>"));
            assert!(payload_source.contains("T:norito::core::SerializePayload"));
        }
    }
}

#[test]
fn serialization_derives_differ_only_by_the_requested_archived_alias() {
    for input in [
        syn::parse_quote! { struct Record<T> { value: T } },
        syn::parse_quote! { struct Record<T>(T); },
        syn::parse_quote! { struct Record; },
        syn::parse_quote! { enum Record<T> { Unit, Value(T), Named { value: T } } },
    ] {
        let mut input: DeriveInput = input;
        let generate = |input: &DeriveInput, archived| match &input.data {
            Data::Struct(data) => derive_struct_serialize(
                &input.ident,
                &input.generics,
                &data.fields,
                &input.attrs,
                archived,
            ),
            Data::Enum(data) => {
                derive_enum_serialize(&input.ident, &input.generics, data, &input.attrs, archived)
            }
            Data::Union(_) => unreachable!(),
        };
        let payload: syn::File = syn::parse2(generate(&input, false)).expect("valid payload impl");
        let archived: syn::File =
            syn::parse2(generate(&input, true)).expect("valid alias and impl");
        assert_eq!(payload.items.len(), 1);
        assert_eq!(archived.items.len(), 2);
        let syn::Item::Type(alias) = &archived.items[0] else {
            panic!("NoritoSerialize must retain its archived alias");
        };
        assert_eq!(alias.ident, "ArchivedRecord");
        let archived_payload = &archived.items[1];
        let payload_source = compact(quote!(#payload));
        assert_eq!(payload_source, compact(quote!(#archived_payload)));
        assert!(payload_source.contains("norito::core::SerializePayload"));
        for forbidden in [
            "NoritoSerialize",
            "NoritoSchema",
            "schema_hash",
            "IntoSchema",
            "type_name",
            "module_path",
            "schema-structural",
        ] {
            assert!(
                !payload_source.contains(forbidden),
                "{forbidden}: {payload_source}"
            );
        }
        if !input.generics.params.is_empty() {
            assert!(payload_source.contains("T:norito::core::SerializePayload"));
        }
        input
            .attrs
            .push(syn::parse_quote!(#[norito(reuse_archived)]));
        assert_eq!(payload_source, compact(generate(&input, true)));
    }
}

#[test]
fn enum_byte_array_fields_use_the_exact_raw_field_helper() {
    let input: DeriveInput = syn::parse_quote! {
        enum RawFields {
            Tuple([u8; 2]),
            Named { bytes: [u8; 2] },
            Values(Vec<u16>),
        }
    };
    let Data::Enum(data) = &input.data else {
        unreachable!("test input is an enum");
    };
    let expansion = compact(derive_enum_deserialize(
        &input.ident,
        &input.generics,
        data,
        &input.attrs,
    ));
    assert_eq!(
        expansion.matches("decode_context_framed_byte_array::<{2}>(ptr,&mutoffset)?").count(),
        2,
        "both enum field forms must follow their raw-byte encoder"
    );
    assert!(expansion.contains("finish_context_fields(ptr,offset)"));
    assert!(!expansion.contains("decode_context_field_canonical::<[u8;2]>"));
    assert!(expansion.contains("decode_context_field_canonical::<Vec<u16>>(ptr,&mutoffset)"));
}
