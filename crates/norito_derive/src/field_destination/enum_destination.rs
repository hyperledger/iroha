//! Sole canonical enum materialization for ordinary and actual-value destinations.

use super::*;

pub(crate) fn derive(
    ident: &syn::Ident,
    generics: &Generics,
    data: &DataEnum,
    attributes: &[Attribute],
    attrs: &ContainerAttr,
) -> TokenStream2 {
    if !generics.params.is_empty() || generics.where_clause.is_some() {
        return syn::Error::new_spanned(
            generics,
            "decode_fields requires a closed enum without generic parameters",
        )
        .to_compile_error();
    }
    let discriminants = match enum_variant_indices(data) {
        Ok(indices) => indices,
        Err(error) => return error.to_compile_error(),
    };
    let mut bounds = generics.clone();
    let mut destination_bounds = Vec::new();
    let mut arms = Vec::new();
    for (variant, disc) in data.variants.iter().zip(discriminants) {
        let name = &variant.ident;
        let parsed = struct_fields(&variant.fields);
        let mut reads = Vec::new();
        let mut bindings = Vec::new();
        let mut restores = Vec::new();
        for (index, field) in parsed.iter().enumerate() {
            if field.attrs.skip || field.attrs.flatten {
                return syn::Error::new_spanned(
                    field.field,
                    "decode_fields requires every enum field; skip and flatten are unsupported",
                )
                .to_compile_error();
            }
            let ty = &field.field.ty;
            let binding = format_ident!("__field_{index}");
            // Match the sole ordinary enum field decoder: direct byte arrays
            // carry raw bytes; every other child uses its canonical value frame.
            let read = if let Some(length) = u8_array_len(ty) {
                quote!(norito::core::framed_byte_array_field::<{ #length }>(__bytes,&mut __offset)?)
            } else {
                add_bound(
                    &mut bounds,
                    ty,
                    quote!(for<'__d> norito::core::DeserializePayload<'__d>),
                );
                add_bound(&mut bounds, ty, quote!(norito::core::SerializePayload));
                quote!(norito::core::framed_field::<#ty>(__bytes,&mut __offset)?)
            };
            destination_bounds
                .push(quote!(__Destination:norito::core::DecodeVariantField<#disc,#index,#ty>));
            let prior = restores.iter().rev();
            reads.push(quote! {
                let #binding=match (|| -> ::core::result::Result<#ty,norito::core::DecodeIntoError<__Destination::Error>> {
                    <__Destination as norito::core::DecodeVariantField<#disc,#index,#ty>>::decode_variant_field(
                        __destination,#read
                    )
                })() {
                    Ok(value)=>value,
                    Err(error)=> {
                        #(#prior)*
                        return Err(error);
                    }
                };
            });
            restores.push(quote! {
                <__Destination as norito::core::DecodeVariantField<#disc,#index,#ty>>::restore_variant_field(
                    __destination,#binding
                );
            });
            bindings.push(binding);
        }
        let construct = match &variant.fields {
            Fields::Unit => quote!(Self::#name),
            Fields::Unnamed(_) => quote!(Self::#name(#(#bindings),*)),
            Fields::Named(fields) => {
                let names = fields
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().expect("named enum field"));
                quote!(Self::#name {#(#names:#bindings),*})
            }
        };
        arms.push(quote! {
            #disc=> {
                norito::core::EnumFieldDestination::begin_variant(__destination,#disc)
                    .map_err(norito::core::DecodeIntoError::Destination)?;
                #(#reads)*
                #construct
            }
        });
    }
    let validated = decode_validation::value(attrs.validate.as_ref(), quote!(__value));
    let slice = slice_decode::derive(ident, &bounds, attributes, slice_decode::DecodeBody::Prefix);
    quote! {
        impl<__Destination> norito::core::DecodeValueFields<__Destination> for #ident
        where
            __Destination:norito::core::EnumFieldDestination + norito::core::DecodeValueDestination<#ident>,
            #(#destination_bounds,)*
        {
            fn decode_value_fields(__bytes:&[u8],__destination:&mut __Destination)
                ->::core::result::Result<(Self,usize),norito::core::DecodeIntoError<__Destination::Error>>
            {
                let _context=norito::core::PayloadCtxGuard::enter(__bytes);
                let mut __tag_bytes=[0u8;4];
                __tag_bytes.copy_from_slice(norito::core::payload_range_from_ptr(__bytes.as_ptr(),4)?);
                let __tag=u32::from_le_bytes(__tag_bytes);
                let mut __offset=4usize;
                let __value=match __tag {
                    #(#arms,)*
                    _=>return Err(norito::core::DecodeIntoError::Codec(norito::core::Error::Message("invalid enum discriminant".into()))),
                };
                if let Err(error)=norito::core::finish_context_fields(__bytes.as_ptr(),__offset) {
                    <__Destination as norito::core::DecodeValueDestination<Self>>::restore_value(
                        __destination,__value
                    );
                    return Err(norito::core::DecodeIntoError::Codec(error));
                }
                let __value=(#validated).map_err(norito::core::DecodeIntoError::Codec)?;
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
    }
}
