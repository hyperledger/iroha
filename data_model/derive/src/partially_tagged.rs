#![allow(clippy::too_many_lines)]
use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_quote,
    punctuated::Punctuated,
    Attribute, Generics, Ident, Token, Type, Variant, Visibility,
};

pub struct PartiallyTaggedEnum {
    attrs: Vec<Attribute>,
    ident: Ident,
    variants: Punctuated<PartiallyTaggedVariant, Token![,]>,
    generics: Generics,
}

pub struct PartiallyTaggedVariant {
    attrs: Vec<Attribute>,
    ident: Ident,
    ty: Type,
    is_untagged: bool,
}

impl Parse for PartiallyTaggedEnum {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut attrs = input.call(Attribute::parse_outer)?;
        let _vis = input.parse::<Visibility>()?;
        let _enum_token = input.parse::<Token![enum]>()?;
        let ident = input.parse::<Ident>()?;
        let generics = input.parse::<Generics>()?;
        let content;
        let _brace_token = syn::braced!(content in input);
        let variants = content.parse_terminated(PartiallyTaggedVariant::parse)?;
        attrs.retain(is_serde_attr);
        Ok(PartiallyTaggedEnum {
            attrs,
            ident,
            variants,
            generics,
        })
    }
}

impl Parse for PartiallyTaggedVariant {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let variant = input.parse::<Variant>()?;
        let Variant {
            ident,
            fields,
            mut attrs,
            ..
        } = variant;
        let field = match fields {
            syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => fields
                .unnamed
                .into_iter()
                .next()
                .expect("Guaranteed to have exactly one field"),
            fields => abort!(fields, "Only supports tuple variants with single field"),
        };
        let ty = field.ty;
        let is_untagged = attrs.iter().any(is_untagged_attr);
        attrs.retain(is_serde_attr);
        Ok(PartiallyTaggedVariant {
            attrs,
            ident,
            ty,
            is_untagged,
        })
    }
}

impl PartiallyTaggedEnum {
    fn variants(&self) -> impl Iterator<Item = &PartiallyTaggedVariant> {
        self.variants.iter()
    }

    fn untagged_variants(&self) -> impl Iterator<Item = &PartiallyTaggedVariant> {
        self.variants.iter().filter(|variant| variant.is_untagged)
    }
}

/// Convert from vector of variants to tuple of vectors consisting of variant's fields
fn variants_to_tuple<'lt, I: Iterator<Item = &'lt PartiallyTaggedVariant>>(
    variants: I,
) -> (Vec<&'lt Ident>, Vec<&'lt Type>, Vec<&'lt [Attribute]>) {
    variants.fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut idents, mut types, mut attrs), variant| {
            idents.push(&variant.ident);
            types.push(&variant.ty);
            attrs.push(&variant.attrs);
            (idents, types, attrs)
        },
    )
}

/// Check if enum variant should be treated as untagged
fn is_untagged_attr(attr: &Attribute) -> bool {
    attr == &parse_quote!(#[serde_partially_tagged(untagged)])
}

/// Check if `#[serde...]` attribute
fn is_serde_attr(attr: &Attribute) -> bool {
    attr.path
        .get_ident()
        .map_or_else(|| false, |ident| ident.to_string().eq("serde"))
}

pub fn impl_partially_tagged_serialize(enum_: &PartiallyTaggedEnum) -> TokenStream {
    let enum_ident = &enum_.ident;
    let enum_attrs = &enum_.attrs;
    let ref_internal_repr_ident = format_ident!("{}RefInternalRepr", enum_ident);
    let ser_helper = format_ident!("{}SerializeHelper", enum_ident);
    let (variants_ident, variants_ty, variants_attrs) = variants_to_tuple(enum_.variants());
    let (untagged_variants_ident, untagged_variants_ty, untagged_variants_attrs) =
        variants_to_tuple(enum_.untagged_variants());
    let serialize_trait_bound: syn::TypeParamBound = parse_quote!(::serde::Serialize);
    let mut generics = enum_.generics.clone();
    generics
        .type_params_mut()
        .for_each(|type_| type_.bounds.push(serialize_trait_bound.clone()));
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let mut ref_internal_generics = enum_.generics.clone();
    ref_internal_generics.params.push(parse_quote!('re));
    let (ref_internal_impl_generics, ref_internal_type_generics, ref_internal_where_clause) =
        ref_internal_generics.split_for_impl();

    quote! {
        impl #impl_generics ::serde::Serialize for #enum_ident #type_generics #where_clause {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                #[derive(::serde::Serialize)]
                #(#enum_attrs)*
                enum #ref_internal_repr_ident #ref_internal_generics {
                    #(
                        #(
                            #variants_attrs
                        )*
                        #variants_ident(&'re #variants_ty),
                    )*
                }

                #[inline]
                fn convert #ref_internal_impl_generics (value: &'re #enum_ident #type_generics) -> #ref_internal_repr_ident #ref_internal_type_generics #ref_internal_where_clause {
                    match value {
                        #(
                            #enum_ident::#variants_ident(value) => #ref_internal_repr_ident::#variants_ident(value),
                        )*
                    }
                }

                #[derive(::serde::Serialize)]
                #[serde(untagged)] // Unaffected by #3330, because Serialize implementations are unaffected
                enum #ser_helper #ref_internal_generics {
                    #(
                        #(
                            #untagged_variants_attrs
                        )*
                        #untagged_variants_ident(&'re #untagged_variants_ty),
                    )*
                    Other(#ref_internal_repr_ident #ref_internal_type_generics),
                }

                let wrapper = match self {
                    #(
                        #enum_ident::#untagged_variants_ident(value) => #ser_helper::#untagged_variants_ident(value),
                    )*
                    value => #ser_helper::Other(convert(value)),
                };

                wrapper.serialize(serializer)
            }
        }
    }
    .into()
}

pub fn impl_partially_tagged_deserialize(enum_: &PartiallyTaggedEnum) -> TokenStream {
    let enum_ident = &enum_.ident;
    let enum_attrs = &enum_.attrs;
    let internal_repr_ident = format_ident!("{}InternalRepr", enum_ident);
    let deser_helper = format_ident!("{}DeserializeHelper", enum_ident);
    let no_successful_untagged_variant_match =
        format!("Data did not match any variant of enum {}", deser_helper);
    let (variants_ident, variants_ty, variants_attrs) = variants_to_tuple(enum_.variants());
    let (untagged_variants_ident, untagged_variants_ty, untagged_variants_attrs) =
        variants_to_tuple(enum_.untagged_variants());
    let deserialize_trait_bound: syn::TypeParamBound = parse_quote!(::serde::de::DeserializeOwned);
    let variants_ty_deserialize_bound = variants_ty
        .iter()
        .map(|ty| quote!(#ty: #deserialize_trait_bound).to_string())
        .collect::<Vec<_>>();
    let mut generics = enum_.generics.clone();
    generics.type_params_mut().for_each(|type_| {
        type_.bounds.push(deserialize_trait_bound.clone());
    });
    let (_, type_generics, where_clause) = generics.split_for_impl();
    let mut generics = generics.clone();
    generics.params.push(parse_quote!('de));
    let (impl_generics, _, _) = generics.split_for_impl();
    let internal_repr_generics = enum_.generics.clone();
    let (internal_repr_impl_generics, internal_repr_type_generics, internal_repr_where_clause) =
        internal_repr_generics.split_for_impl();

    quote! {
        impl #impl_generics ::serde::Deserialize<'de> for #enum_ident #type_generics #where_clause {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                #[derive(::serde::Deserialize, Debug)]
                #(
                    #enum_attrs
                )*
                enum #internal_repr_ident #internal_repr_generics {
                    #(
                        #(
                            #variants_attrs
                        )*
                        #[serde(bound(deserialize = #variants_ty_deserialize_bound))]
                        #variants_ident(#variants_ty),
                    )*
                }

                #[inline]
                fn convert #internal_repr_impl_generics (internal: #internal_repr_ident #internal_repr_type_generics) -> #enum_ident #internal_repr_type_generics #internal_repr_where_clause {
                    match internal {
                        #(
                            #internal_repr_ident::#variants_ident(value) => #enum_ident::#variants_ident(value),
                        )*
                    }
                }

                // FIXME: Due to an oversight in handling of `u128`
                // values, an untagged containing a `u128` value will
                // always fail to deserialize, thus
                // #[derive(::serde::Deserialize)] #[serde(untagged)]
                // is replaced with a manual implementation until
                // further notice.
                //
                // Also note that this struct isn't necessary for the
                // current manual implementation of partially tagged
                // enums, but is needed to neatly return the
                // derive-based solution.#
                #[derive(Debug)]
                enum #deser_helper #internal_repr_generics {
                    #(
                        #(
                            #untagged_variants_attrs
                        )*
                        #untagged_variants_ident(#untagged_variants_ty),
                    )*
                    Other(#internal_repr_ident #internal_repr_type_generics),
                }

                // TODO: remove once `serde::__private::ContentDeserializer` properly handles `u128`.
                // Tracking issue: https://github.com/serde-rs/serde/issues/2230
                impl #impl_generics ::serde::Deserialize<'de> for #deser_helper #type_generics #where_clause {
                    fn deserialize<D: ::serde::Deserializer<'de>>(
                        deserializer: D,
                    ) -> Result<Self, D::Error> {
                        #[cfg(feature = "std")]
                        let mut errors = Vec::new();
                        #[cfg(feature = "std")]
                        let mut unmatched_enums = Vec::new();

                        let content = serde_json::Value::deserialize(deserializer)?;
                        #(
                            {
                                let candidate_variant = #untagged_variants_ty::deserialize(&content);
                                match candidate_variant {
                                    Ok(candidate) => return Ok(
                                        #deser_helper::#untagged_variants_ident(candidate)
                                    ),
                                    Err(error) => {
                                        #[cfg(feature = "std")]
                                        {
                                            let msg = error.to_string();
                                            if msg.starts_with("unknown variant") {
                                                unmatched_enums.push((msg, stringify!(#untagged_variants_ty)));
                                            } else {
                                                errors.push((msg, stringify!(#untagged_variants_ty)));
                                            }
                                        }
                                    }
                                }
                            }
                        )*
                        {
                            let candidate_variant = #internal_repr_ident::deserialize(content);
                            match candidate_variant {
                                Ok(candidate) => return Ok(#deser_helper::Other(candidate)),
                                Err(error) => {
                                    #[cfg(feature = "std")]
                                    {
                                        let msg = error.to_string();
                                        if msg.starts_with("unknown variant") {
                                            unmatched_enums.push((msg, stringify!(#internal_repr_ident)));
                                        } else {
                                            errors.push((msg, stringify!(#internal_repr_ident)));
                                        }
                                    }
                                }
                            }
                        }
                        #[cfg(feature = "std")]
                        {
                            let mut message = #no_successful_untagged_variant_match.to_string();
                            for (error, candidate_type) in unmatched_enums {
                                message +="Candidate `";
                                message += &candidate_type;
                                message += "` unsuitable: ";
                                message += &error;
                                message += "\n";
                            }
                            message+="\n--------------\n";
                            for (error, candidate_type) in errors {
                                message +="Candidate `";
                                message += &candidate_type;
                                message += "` failed to deserialize with error: ";
                                message += &error;
                                message += "\n";
                            }
                            Err(::serde::de::Error::custom(message))
                        }
                        #[cfg(not(feature = "std"))]
                        Err(::serde::de::Error::custom(#no_successful_untagged_variant_match))
                    }
                }

                let wrapper = #deser_helper::deserialize(deserializer)?;
                match wrapper {
                    #(
                        #deser_helper::#untagged_variants_ident(value) => Ok(#enum_ident::#untagged_variants_ident(value)),
                    )*
                    #deser_helper::Other(value) => Ok(convert(value)),
                }
            }
        }
    }
    .into()
}
