//! One derived positional record walk for ordinary and prepared custody.

use super::*;

pub(super) fn derive(
    ident: &syn::Ident,
    generics: &Generics,
    fields: &Fields,
    attributes: &[Attribute],
    attrs: &ContainerAttr,
) -> TokenStream2 {
    if matches!(fields, Fields::Unit) {
        return syn::Error::new_spanned(ident, "decode_fields requires a closed positional record")
            .to_compile_error();
    }
    if !generics.params.is_empty() || generics.where_clause.is_some() {
        return syn::Error::new_spanned(
            generics,
            "decode_fields requires a closed positional record without generic parameters",
        )
        .to_compile_error();
    }
    let parsed = struct_fields(fields);
    for field in &parsed {
        if field.attrs.flatten {
            return syn::Error::new_spanned(
                field.field,
                "decode_fields does not support flattened positional fields",
            )
            .to_compile_error();
        }
    }
    let mut bounds = generics.clone();
    let wire_fields: Vec<_> = parsed
        .iter()
        .enumerate()
        .filter(|(_, field)| !field.attrs.skip)
        .collect();
    let types: Vec<_> = wire_fields
        .iter()
        .map(|(_, field)| &field.field.ty)
        .collect();
    let indices: Vec<_> = wire_fields.iter().map(|(index, _)| *index).collect();
    let bindings: Vec<_> = indices
        .iter()
        .map(|index| format_ident!("__field_{index}"))
        .collect();
    let reconstructed: Vec<_> = parsed
        .iter()
        .enumerate()
        .map(|(index, field)| {
            if field.attrs.skip {
                let ty = &field.field.ty;
                add_bound(&mut bounds, ty, quote!(::core::default::Default));
                quote!(::core::default::Default::default())
            } else {
                let binding = format_ident!("__field_{index}");
                quote!(#binding)
            }
        })
        .collect();
    let reconstruct = match fields {
        Fields::Named(named) => {
            let names = named
                .named
                .iter()
                .map(|field| field.ident.as_ref().expect("named fields"));
            quote! { Self { #(#names:#reconstructed,)* } }
        }
        Fields::Unnamed(_) => quote! { Self(#(#reconstructed,)*) },
        Fields::Unit => unreachable!("unit records were rejected above"),
    };
    let reads: Vec<_> = wire_fields.iter().map(|(_, field)| {
        let ty=&field.field.ty;
        if let Some(length)=u8_array_len(ty) {
            quote! { norito::core::framed_byte_array_field::<{#length}>(__bytes, &mut __offset)? }
        } else {
            add_bound(&mut bounds,ty,quote!(for<'__d> norito::core::DeserializePayload<'__d>));
            add_bound(&mut bounds,ty,quote!(norito::core::SerializePayload));
            quote! { norito::core::framed_field::<#ty>(__bytes, &mut __offset)? }
        }
    }).collect();
    // Tuple slice decoding keeps its original archived whole-input contract;
    // named records retain their existing prefix decoder. Both ordinary paths
    // reconstruct through this same positional kernel and keep original framing.
    let slice_body = if matches!(fields, Fields::Unnamed(_)) {
        slice_decode::DecodeBody::Archived(quote! {
            let value = <Self as norito::core::DeserializePayload>::try_deserialize(__archived)?;
            Ok((value,__logical_len))
        })
    } else {
        slice_decode::DecodeBody::Prefix
    };
    let slice = slice_decode::derive(ident, &bounds, attributes, slice_body);
    if let Some(hook) = &attrs.validate {
        // A consuming hook may normalize Self. Returning () field results would
        // let a destination keep the unvalidated/unnormalized storage while the
        // caller ignored the hook's actual return. Only materialization of the
        // concrete declared fields can enter this validated value path.
        return quote! {
            impl<__Destination> norito::core::DecodeValueFields<__Destination> for #ident
            where
                __Destination: norito::core::FieldDestination,
                #(__Destination: norito::core::DecodeField<#indices,#types,Value=#types>,)*
            {
                fn decode_value_fields(__bytes:&[u8],__destination:&mut __Destination)
                    -> ::core::result::Result<(Self,usize),norito::core::DecodeIntoError<__Destination::Error>>
                {
                    let _context=norito::core::PayloadCtxGuard::enter(__bytes);
                    let mut __offset=0usize;
                    #(let #bindings=<__Destination as norito::core::DecodeField<#indices,#types>>::decode_field(__destination,#reads)?;)*
                    norito::core::finish_context_fields(__bytes.as_ptr(),__offset)?;
                    let __value=#hook(#reconstruct).map_err(norito::core::DecodeIntoError::Codec)?;
                    Ok((__value,__offset))
                }
            }
            impl<'de> norito::core::DeserializePayload<'de> for #ident {
                fn deserialize(archived:&'de norito::core::Archived<Self>)->Self {
                    <Self as norito::core::DeserializePayload<'de>>::try_deserialize(archived)
                        .unwrap_or_else(|error|panic!("norito: fallible deserialize failed for {}: {:?}",stringify!(#ident),error))
                }
                fn try_deserialize(archived:&'de norito::core::Archived<Self>)->::core::result::Result<Self,norito::core::Error> {
                    norito::core::with_context_fields(archived as *const _ as *const u8,|__bytes| {
                        <Self as norito::core::DecodeValueFields<norito::core::OwnedFields>>::decode_value_fields(__bytes,&mut norito::core::OwnedFields)
                            .map(|(value,_)|value).map_err(norito::core::DecodeIntoError::into_codec)
                    })?
                }
            }
            #slice
        };
    }
    quote! {
        impl<__Destination> norito::core::DecodeRecordFields<__Destination> for #ident
        where
            __Destination: norito::core::FieldDestination,
            #(__Destination: norito::core::DecodeField<#indices, #types>,)*
        {
            type Values = (#(<__Destination as norito::core::DecodeField<#indices,#types>>::Value,)*);
            fn decode_fields(__bytes: &[u8], __destination: &mut __Destination)
                -> ::core::result::Result<(Self::Values, usize), norito::core::DecodeIntoError<__Destination::Error>>
            {
                let _context = norito::core::PayloadCtxGuard::enter(__bytes);
                let mut __offset=0usize;
                #(let #bindings = <__Destination as norito::core::DecodeField<#indices,#types>>::decode_field(__destination, #reads)?;)*
                norito::core::finish_context_fields(__bytes.as_ptr(), __offset)?;
                Ok(((#(#bindings,)*),__offset))
            }
        }
        impl<'de> norito::core::DeserializePayload<'de> for #ident {
            fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
                <Self as norito::core::DeserializePayload<'de>>::try_deserialize(archived).unwrap_or_else(|error| panic!("norito: fallible deserialize failed for {}: {:?}", stringify!(#ident),error))
            }
            fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> ::core::result::Result<Self,norito::core::Error> {
                let ((#(#bindings,)*),_) = norito::core::with_context_fields(archived as *const _ as *const u8, |__bytes| {
                    <Self as norito::core::DecodeRecordFields<norito::core::OwnedFields>>::decode_fields(__bytes,&mut norito::core::OwnedFields)
                        .map_err(norito::core::DecodeIntoError::into_codec)
                })??;
                Ok(#reconstruct)
            }
        }
        #slice
    }
}

mod enum_destination;
pub(super) use enum_destination::derive as derive_enum;

#[cfg(test)]
mod tests;
