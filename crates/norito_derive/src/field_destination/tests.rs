//! Derived field-walk registration, type shape and unsupported-contract controls.

use super::*;
use syn::{Data, DeriveInput};

fn expansion(input: DeriveInput) -> TokenStream2 {
    let Data::Struct(record) = &input.data else {
        panic!("record fixture")
    };
    derive(
        &input.ident,
        &input.generics,
        &record.fields,
        &input.attrs,
        &ContainerAttr::parse(&input.attrs).unwrap(),
    )
}

#[test]
fn generated_owned_record_calls_one_destination_walk_with_exact_positional_types() {
    let output = expansion(syn::parse_quote! {
        #[norito(decode_fields,decode_from_slice)]
        struct Example { first:u64, fixed:[u8;32], bytes:Vec<u8> }
    });
    let file: syn::File = syn::parse2(output.clone()).expect("complete generated implementations");
    assert_eq!(
        file.items.len(),
        3,
        "record visitor, owned payload, and requested slice implementation"
    );
    let text = output.to_string();
    assert_eq!(text.matches("fn decode_fields").count(), 1);
    assert_eq!(text.matches("framed_field :: <").count(), 2);
    assert_eq!(text.matches("framed_byte_array_field").count(), 1);
    assert!(text.contains("DecodeField < 0usize , u64 >"));
    assert!(text.contains("DecodeField < 1usize , [u8 ; 32] >"));
    assert!(text.contains("DecodeField < 2usize , Vec < u8 > >"));
    assert!(text.contains("DecodeRecordFields < norito :: core :: OwnedFields >"));
    assert!(
        !text.contains("decode_context_field_canonical"),
        "owned decoder must not retain a parallel field parser"
    );
}

#[test]
fn destination_walk_rejects_unimplemented_shape_contracts() {
    let cases: [(DeriveInput, &str); 3] = [
        (
            syn::parse_quote! { #[norito(decode_fields)] struct Unit; },
            "closed positional record",
        ),
        (
            syn::parse_quote! { #[norito(decode_fields)] struct Generic<T>{value:T} },
            "without generic parameters",
        ),
        (
            syn::parse_quote! { #[norito(decode_fields)] struct Flat { #[norito(flatten)] value:u8 } },
            "does not support flattened positional fields",
        ),
    ];
    for (input, message) in cases {
        let tokens = expansion(input).to_string();
        assert!(tokens.contains("compile_error"));
        assert!(tokens.contains(message), "{tokens}");
    }
}

#[test]
fn destination_flag_rejects_duplicate_and_valued_spellings() {
    for (input, expected) in [
        (
            syn::parse_quote! {#[norito(decode_fields,decode_fields)] struct R{}},
            "duplicate decode_fields attribute",
        ),
        (
            syn::parse_quote! {#[norito(decode_fields=true)] struct R{}},
            "decode_fields does not take a value",
        ),
    ] {
        let input: DeriveInput = input;
        assert_eq!(
            ContainerAttr::parse(&input.attrs)
                .err()
                .unwrap()
                .to_string(),
            expected
        );
    }
}

#[test]
fn generated_tuple_uses_sole_positional_walk_and_original_archived_slice_contract() {
    let output = expansion(
        syn::parse_quote! { #[norito(decode_fields,decode_from_slice)] struct Tuple(u32,[u8;4],u64); },
    );
    let file: syn::File = syn::parse2(output.clone()).expect("complete tuple implementations");
    assert_eq!(file.items.len(), 3);
    let text = output.to_string();
    assert_eq!(text.matches("fn decode_fields").count(), 1);
    assert_eq!(text.matches("framed_field :: <").count(), 2);
    assert_eq!(text.matches("framed_byte_array_field").count(), 1);
    assert!(text.contains("DecodeField < 0usize , u32 >"));
    assert!(text.contains("DecodeField < 1usize , [u8 ; 4] >"));
    assert!(text.contains("DecodeField < 2usize , u64 >"));
    assert!(text.contains("Self (__field_0 , __field_1 , __field_2 ,)"));
    assert!(text.contains("Ok ((value , __logical_len))"));
    assert!(!text.contains("decode_context_field_canonical"));
    assert!(!text.contains("decode_prepared_slice_prefix"));
}

#[test]
fn validated_record_materializes_actual_hook_output_and_cannot_mint_a_span_only_value() {
    let output = expansion(syn::parse_quote! {
        #[norito(decode_fields,validate="Self::normalize",decode_from_slice)]
        struct Checked {value:u8,fixed:[u8;4]}
    });
    syn::parse2::<syn::File>(output.clone()).expect("complete validating materializer");
    let text = output.to_string();
    assert_eq!(text.matches("fn decode_value_fields").count(), 1);
    assert_eq!(text.matches("Self :: normalize (").count(), 1);
    assert!(text.contains("Value = u8"));
    assert!(text.contains("Value = [u8 ; 4]"));
    assert!(text.contains("DecodeValueFields < norito :: core :: OwnedFields >"));
    assert!(!text.contains("DecodeRecordFields"));
    assert!(!text.contains("decode_context_field_canonical"));
    assert!(
        text.find("finish_context_fields").unwrap() < text.find("Self :: normalize (").unwrap()
    );
    assert!(text.contains("Ok ((__value , __offset))"));
}

fn enum_expansion(input: DeriveInput) -> TokenStream2 {
    let Data::Enum(data) = &input.data else {
        panic!("enum fixture")
    };
    derive_enum(
        &input.ident,
        &input.generics,
        data,
        &input.attrs,
        &ContainerAttr::parse(&input.attrs).unwrap(),
    )
}

#[test]
fn enum_materializer_keeps_original_tags_variant_indices_and_normal_array_framing() {
    let output = enum_expansion(syn::parse_quote! {
        #[norito(decode_fields,validate="Self::normalize",decode_from_slice)]
        enum Choice {
            #[codec(index=7)] Unit,
            #[codec(index=19)] Tuple(u8,[u8;4]),
            Named {value:u16},
        }
    });
    syn::parse2::<syn::File>(output.clone()).expect("complete canonical enum materializer");
    let text = output.to_string();
    assert_eq!(text.matches("fn decode_value_fields").count(), 1);
    assert_eq!(text.matches("u32 :: from_le_bytes").count(), 1);
    assert_eq!(text.matches("begin_variant").count(), 3);
    assert_eq!(text.matches("framed_field :: <").count(), 2);
    assert_eq!(text.matches("framed_byte_array_field :: <").count(), 1);
    assert!(text.contains("DecodeVariantField < 19u32 , 1usize , [u8 ; 4] >"));
    assert!(text.contains("DecodeVariantField < 2u32 , 0usize , u16 >"));
    assert_eq!(text.matches("Self :: normalize (").count(), 1);
    assert!(
        text.find("finish_context_fields").unwrap() < text.find("Self :: normalize (").unwrap()
    );
    assert!(!text.contains("decode_context_field_canonical"));
    assert!(text.contains("invalid enum discriminant"));
    assert!(text.contains("DecodeValueFields < norito :: core :: OwnedFields >"));
}

#[test]
fn enum_materializer_rejects_nonclosed_skipped_flattened_and_duplicate_variant_contracts() {
    for (input, message) in [
        (
            syn::parse_quote! {#[norito(decode_fields)] enum Generic<T>{One(T)}},
            "without generic parameters",
        ),
        (
            syn::parse_quote! {#[norito(decode_fields)] enum Skipped{One(#[norito(skip)]u8)}},
            "skip and flatten are unsupported",
        ),
        (
            syn::parse_quote! {#[norito(decode_fields)] enum Flat{One{#[norito(flatten)] value:u8}}},
            "skip and flatten are unsupported",
        ),
        (
            syn::parse_quote! {#[norito(decode_fields)] enum Duplicate{#[codec(index=1)]A,B}},
            "duplicate",
        ),
    ] {
        let output = enum_expansion(input).to_string();
        assert!(output.contains("compile_error"), "{output}");
        assert!(output.contains(message), "{output}");
    }
}

#[test]
fn enum_result_rollback_keeps_actual_coordinates_and_original_error_without_hook_recovery() {
    let output = enum_expansion(syn::parse_quote! {
        #[norito(decode_fields,validate="Self::normalize",decode_from_slice)]
        enum Choice {
            #[codec(index=23)]
            Named {first:Box<[u8;8]>,second:Box<[u8;8]>,last:u8},
        }
    });
    syn::parse2::<syn::File>(output.clone()).expect("complete typed rollback materializer");
    let text = output.to_string();
    assert_eq!(text.matches("fn decode_value_fields").count(), 1);
    assert_eq!(text.matches("restore_variant_field").count(), 3);
    assert_eq!(text.matches("restore_value").count(), 1);
    assert_eq!(text.matches("return Err (error)").count(), 3);
    assert_eq!(text.matches("Self :: normalize (").count(), 1);
    assert!(text.contains("DecodeVariantField < 23u32 , 0usize , Box < [u8 ; 8] > >"));
    assert!(text.contains("DecodeVariantField < 23u32 , 1usize , Box < [u8 ; 8] > >"));
    let finish = text.find("finish_context_fields").unwrap();
    let hook = text.find("Self :: normalize (").unwrap();
    assert!(finish < hook);
    assert!(!text[hook..].contains("restore_variant_field"));
    assert!(!text[hook..].contains("restore_value"));
    assert!(!text.contains("clone"));
    assert!(!text.contains("decode_context_field_canonical"));
}

#[test]
fn skipped_record_fields_have_no_wire_callback_and_default_only_on_reconstruction() {
    for input in [
        syn::parse_quote! {
            #[norito(decode_fields,decode_from_slice)]
            struct Cached { first:u8, #[norito(skip)] middle:u16, last:u32, #[norito(skip)] tail:u64 }
        },
        syn::parse_quote! {
            #[norito(decode_fields,decode_from_slice)]
            struct Cached(u8, #[norito(skip)] u16, u32, #[norito(skip)] u64);
        },
        syn::parse_quote! {
            #[norito(decode_fields,decode_from_slice,validate="Self::validate")]
            struct Cached { first:u8, #[norito(skip)] middle:u16, last:u32, #[norito(skip)] tail:u64 }
        },
    ] {
        let output = expansion(input);
        syn::parse2::<syn::File>(output.clone()).expect("complete skipped-field implementations");
        let text = output.to_string();
        assert!(text.contains("DecodeField < 0usize , u8"));
        assert!(text.contains("DecodeField < 2usize , u32"));
        assert!(!text.contains("DecodeField < 1usize"));
        assert!(!text.contains("DecodeField < 3usize"));
        assert_eq!(text.matches("framed_field :: <").count(), 2);
        assert_eq!(text.matches("Default :: default ()").count(), 2);
        let finish = text.find("finish_context_fields").unwrap();
        let first_default = text.find("Default :: default ()").unwrap();
        assert!(finish < first_default);
    }
}
