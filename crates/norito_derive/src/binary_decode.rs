//! Binary payload reconstruction and canonical slice decoder generation.

use super::*;

fn decode_from_archived_body() -> TokenStream2 {
    quote! {
        let value = <Self as norito::core::DeserializePayload>::try_deserialize(
            __archived,
        )?;
        Ok((value, __logical_len))
    }
}

fn sequential_deserialize_value(
    field: &StructField<'_>,
    generics: &mut Generics,
) -> Option<TokenStream2> {
    let ty = &field.field.ty;
    if field.attrs.skip {
        add_bound(generics, ty, quote!(Default));
        return None;
    }
    // Binary V1 fields are positional and mandatory. `default` remains a JSON
    // input policy and must never synthesize an omitted binary field.
    let decode = if field.attrs.flatten {
        add_bound(
            generics,
            ty,
            quote!(for<'__d> norito::core::DecodeFromSlice<'__d>),
        );
        quote! {
            (|| -> ::core::result::Result<#ty, norito::core::Error> {
                let (base, total) = norito::core::payload_ctx()
                    .ok_or(norito::core::Error::MissingPayloadContext)?;
                let start = (ptr as usize).saturating_sub(base);
                let payload = unsafe {
                    std::slice::from_raw_parts(base as *const u8, total)
                };
                let field_data = payload
                    .get(start + offset..)
                    .ok_or(norito::core::Error::LengthMismatch)?;
                let (value, consumed) =
                    <#ty as norito::core::DecodeFromSlice>::decode_from_slice(field_data)?;
                offset += consumed;
                Ok(value)
            })()
        }
    } else if let Some(length) = u8_array_len(ty) {
        quote! {
            norito::core::decode_context_framed_byte_array::<{ #length }>(ptr, &mut offset)
        }
    } else {
        add_bound(
            generics,
            ty,
            quote!(for<'__d> norito::core::DeserializePayload<'__d>),
        );
        add_bound(generics, ty, quote!(norito::core::SerializePayload));
        quote! {
            norito::core::decode_context_field_canonical::<#ty>(ptr, &mut offset)
        }
    };
    Some(quote! { (#decode)? })
}

/// Decode one enum-variant field from its length-prefixed frame.
fn enum_field_decode(generics: &mut Generics, ty: &syn::Type) -> TokenStream2 {
    if let Some(length) = u8_array_len(ty) {
        return quote! {
            norito::core::decode_context_framed_byte_array::<{ #length }>(ptr, &mut offset)?
        };
    }
    add_bound(
        generics,
        ty,
        quote!(for<'__d> norito::core::DeserializePayload<'__d>),
    );
    add_bound(generics, ty, quote!(norito::core::SerializePayload));
    quote! {
        norito::core::decode_context_field_canonical::<#ty>(ptr, &mut offset)?
    }
}

/// Generate payload reconstruction with optional validation and slice decoding.
pub(super) fn derive_struct_deserialize(
    ident: &syn::Ident,
    generics: &Generics,
    fields: &Fields,
    container_attrs: &[Attribute],
) -> TokenStream2 {
    let attrs = match ContainerAttr::parse(container_attrs) {
        Ok(attrs) => attrs,
        Err(error) => return error.to_compile_error(),
    };
    if attrs.decode_fields {
        return field_destination::derive(ident, generics, fields, container_attrs, &attrs);
    }
    let validation = attrs.validate;
    let validated_value = decode_validation::value(validation.as_ref(), quote!(__value));
    let mut r#gen = generics.clone();
    let parsed_fields = struct_fields(fields);
    let deserialize_fields = match fields {
        Fields::Named(_) => parsed_fields
            .iter()
            .map(|field| {
                let member = &field.member;
                sequential_deserialize_value(field, &mut r#gen).map_or_else(
                    || quote! { #member: Default::default() },
                    |value| quote! { #member: { #value } },
                )
            })
            .collect::<Vec<_>>(),
        Fields::Unnamed(_) => parsed_fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let binding = format_ident!("field{}", index);
                sequential_deserialize_value(field, &mut r#gen).map_or_else(
                    || quote! { let #binding = Default::default(); },
                    |value| quote! { let #binding = #value; },
                )
            })
            .collect(),
        Fields::Unit => Vec::new(),
    };

    let mut impl_gen = r#gen.clone();
    impl_gen.params.insert(0, syn::parse_quote!('de));
    let (impl_generics, _, where_clause) = impl_gen.split_for_impl();
    let (_, ty_generics, _) = r#gen.split_for_impl();

    match fields {
        Fields::Named(_) => {
            let __decode_from_slice_impl = slice_decode::derive(
                ident,
                &r#gen,
                container_attrs,
                slice_decode::DecodeBody::Prefix,
            );

            quote! {
                impl #impl_generics norito::core::DeserializePayload<'de> for #ident #ty_generics #where_clause {
                    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
                        match <Self as norito::core::DeserializePayload<'de>>::try_deserialize(archived) {
                            Ok(value) => value,
                            Err(err) => panic!(
                                concat!(
                                    "norito: fallible deserialize failed for ",
                                    stringify!(#ident),
                                    ": {:?}"
                                ),
                                err
                            ),
                        }
                    }
                    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> ::core::result::Result<Self, norito::core::Error> {
                        let ptr = archived as *const _ as *const u8;
                        if norito::debug_trace_enabled() {
                            norito::trace_struct_decode(stringify!(#ident), ptr);
                        }
                        let mut offset = 0usize;
                        let __value = Self { #(#deserialize_fields),* };
                        norito::core::finish_context_fields(ptr, offset)?;
                        #validated_value
                    }
                }
                #__decode_from_slice_impl
            }
        }
        Fields::Unnamed(unnamed) => {
            let vars: Vec<_> = (0..unnamed.unnamed.len())
                .map(|i| format_ident!("field{}", i))
                .collect();
            let __decode_from_slice_impl = slice_decode::derive(
                ident,
                &r#gen,
                container_attrs,
                slice_decode::DecodeBody::Archived(decode_from_archived_body()),
            );
            quote! {
                impl #impl_generics norito::core::DeserializePayload<'de> for #ident #ty_generics #where_clause {
                    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
                        match <Self as norito::core::DeserializePayload<'de>>::try_deserialize(archived) {
                            Ok(value) => value,
                            Err(err) => panic!(
                                concat!(
                                    "norito: fallible deserialize failed for ",
                                    stringify!(#ident),
                                    ": {:?}"
                                ),
                                err
                            ),
                        }
                    }
                    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> ::core::result::Result<Self, norito::core::Error> {
                        let ptr = archived as *const _ as *const u8;
                        let mut offset = 0usize;
                        #(#deserialize_fields)*
                        let __value = Self( #(#vars),* );
                        norito::core::finish_context_fields(ptr, offset)?;
                        #validated_value
                    }
                }
                #__decode_from_slice_impl
            }
        }
        Fields::Unit => {
            let unit_methods = decode_validation::unit_methods(ident, validation.as_ref());
            let __decode_from_slice_impl = slice_decode::derive(
                ident,
                &r#gen,
                container_attrs,
                slice_decode::DecodeBody::Archived(decode_from_archived_body()),
            );
            quote! {
                impl #impl_generics norito::core::DeserializePayload<'de> for #ident #ty_generics #where_clause {
                    #unit_methods
                }
                #__decode_from_slice_impl
            }
        }
    }
}

/// Generate enum reconstruction with positional fields and optional slice decoding.
pub(super) fn derive_enum_deserialize(
    ident: &syn::Ident,
    generics: &Generics,
    data: &DataEnum,
    container_attrs: &[Attribute],
) -> TokenStream2 {
    let mut r#gen = generics.clone();
    let validation = match ContainerAttr::parse(container_attrs) {
        Ok(attrs) if attrs.decode_fields => {
            return syn::Error::new_spanned(
                ident,
                "decode_fields requires a closed positional record",
            )
            .to_compile_error();
        }
        Ok(attrs) => attrs.validate,
        Err(error) => return error.to_compile_error(),
    };
    let validated_value = decode_validation::value(validation.as_ref(), quote!(value));
    let mut arms = Vec::new();
    let discriminants = match enum_variant_indices(data) {
        Ok(discriminants) => discriminants,
        Err(error) => return error.to_compile_error(),
    };

    for (variant, disc) in data.variants.iter().zip(discriminants) {
        let v_ident = &variant.ident;
        match &variant.fields {
            Fields::Unit => arms.push(quote! {
                #disc => {
                    let offset = 4usize;
                    norito::core::finish_context_fields(ptr, offset)?;
                    Self::#v_ident
                }
            }),
            Fields::Unnamed(fields) => {
                let deser_stmts: Vec<TokenStream2> = fields
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        let attrs = FieldAttr::parse_validated(&f.attrs);
                        let ty = &f.ty;
                        let idx_var = format_ident!("field{}", i);
                        if attrs.skip {
                            add_bound(&mut r#gen, ty, quote!(Default));
                            quote! {
                                let #idx_var = Default::default();
                            }
                        } else {
                            let decode = enum_field_decode(&mut r#gen, ty);
                            quote! {
                                let #idx_var = #decode;
                            }
                        }
                    })
                    .collect();
                let vars: Vec<_> = (0..fields.unnamed.len())
                    .map(|i| format_ident!("field{}", i))
                    .collect();
                arms.push(quote! {
                    #disc => {
                        let mut offset = 4usize;
                        #(#deser_stmts)*
                        let __value = Self::#v_ident(#(#vars),*);
                        norito::core::finish_context_fields(ptr, offset)?;
                        __value
                    }
                });
            }
            Fields::Named(fields) => {
                let deser_stmts: Vec<TokenStream2> = fields
                    .named
                    .iter()
                    .map(|f| {
                        let attrs = FieldAttr::parse_validated(&f.attrs);
                        let name = f.ident.as_ref().unwrap();
                        let ty = &f.ty;
                        if attrs.skip {
                            add_bound(&mut r#gen, ty, quote!(Default));
                            quote! {
                                let #name = Default::default();
                            }
                        } else {
                            let decode = enum_field_decode(&mut r#gen, ty);
                            quote! {
                                let #name = #decode;
                            }
                        }
                    })
                    .collect();
                let names: Vec<_> = fields
                    .named
                    .iter()
                    .map(|f| f.ident.as_ref().unwrap())
                    .collect();
                arms.push(quote! {
                    #disc => {
                        let mut offset = 4usize;

                        #(#deser_stmts)*

                        let __value = Self::#v_ident { #(#names),* };
                        norito::core::finish_context_fields(ptr, offset)?;
                        __value
                    }
                });
            }
        }
    }

    let mut impl_gen = r#gen.clone();
    impl_gen.params.insert(0, syn::parse_quote!('de));
    let (impl_generics, _, where_clause) = impl_gen.split_for_impl();
    let (_, ty_generics, _) = r#gen.split_for_impl();

    let __decode_from_slice_impl = slice_decode::derive(
        ident,
        &r#gen,
        container_attrs,
        slice_decode::DecodeBody::Prefix,
    );
    quote! {
        impl #impl_generics norito::core::DeserializePayload<'de> for #ident #ty_generics #where_clause {

            fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
                match <Self as norito::core::DeserializePayload<'de>>::try_deserialize(archived) {
                    Ok(value) => value,
                    Err(err) => panic!(
                        concat!(
                            "norito: fallible deserialize failed for ",
                            stringify!(#ident),
                            ": {:?}"
                        ),
                        err
                    ),
                }
            }

            fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> ::core::result::Result<Self, norito::core::Error> {
                let ptr = archived as *const _ as *const u8;
                // Read the tag through the active, length-bounded payload
                // context. Constructing a raw slice here would read beyond a
                // truncated archive before the decoder could return an error.
                let mut __tag_bytes = [0u8; 4];
                __tag_bytes.copy_from_slice(norito::core::payload_range_from_ptr(ptr, 4)?);
                let tag = u32::from_le_bytes(__tag_bytes);
                let value = match tag {
                    #(#arms,)*
                    _ => {
                        return Err(norito::core::Error::Message(
                            "invalid enum discriminant".into(),
                        ))
                    }
                };
                #validated_value
            }
        }
        #__decode_from_slice_impl
    }
}
