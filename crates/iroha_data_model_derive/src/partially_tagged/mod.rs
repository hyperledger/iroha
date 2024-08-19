#![allow(clippy::too_many_lines)]
// darling-generated code triggers this lint
#![allow(clippy::option_if_let_else)]

mod resolve_self;

use darling::{FromDeriveInput, FromVariant};
use manyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_quote, Attribute, Generics, Ident, Type};

#[derive(FromDeriveInput)]
#[darling(forward_attrs(serde), supports(enum_newtype))]
pub struct PartiallyTaggedEnum {
    ident: Ident,
    generics: Generics,
    data: darling::ast::Data<PartiallyTaggedVariant, ()>,
    attrs: Vec<Attribute>,
}

#[derive(FromVariant)]
#[darling(forward_attrs(serde), attributes(serde_partially_tagged))]
pub struct PartiallyTaggedVariant {
    ident: Ident,
    fields: darling::ast::Fields<syn::Type>,
    attrs: Vec<Attribute>,
    #[darling(default)]
    untagged: bool,
}

impl PartiallyTaggedEnum {
    fn variants(&self) -> impl Iterator<Item = &PartiallyTaggedVariant> {
        match &self.data {
            darling::ast::Data::Enum(variants) => variants.iter(),
            _ => unreachable!(
                "Only enums are supported. Enforced by `darling(supports(enum_newtype))`"
            ),
        }
    }

    fn untagged_variants(&self) -> impl Iterator<Item = &PartiallyTaggedVariant> {
        self.variants().filter(|variant| variant.untagged)
    }

    /// Returns a type that corresponds to `Self`, handling the generics as necessary
    fn self_ty(&self) -> syn::Type {
        let ident = &self.ident;
        let (_, type_generics, _) = self.generics.split_for_impl();

        parse_quote!(#ident #type_generics)
    }
}

impl PartiallyTaggedVariant {
    fn ty(&self, self_ty: &syn::Type) -> syn::Type {
        let ty = self.fields.fields.first().expect(
            "BUG: Only newtype enums are supported. Enforced by `darling(supports(enum_newtype))`",
        ).clone();

        resolve_self::resolve_self(self_ty, ty)
    }
}

/// Convert from vector of variants to tuple of vectors consisting of variant's fields
fn variants_to_tuple<'lt, I: Iterator<Item = &'lt PartiallyTaggedVariant>>(
    self_ty: &syn::Type,
    variants: I,
) -> (Vec<&'lt Ident>, Vec<Type>, Vec<&'lt [Attribute]>) {
    variants.fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut idents, mut types, mut attrs), variant| {
            idents.push(&variant.ident);
            types.push(variant.ty(self_ty));
            attrs.push(&variant.attrs);
            (idents, types, attrs)
        },
    )
}

pub fn impl_partially_tagged_serialize(input: &syn::DeriveInput) -> Result<TokenStream> {
    let enum_ = PartiallyTaggedEnum::from_derive_input(input)?;

    let enum_ident = &enum_.ident;
    let enum_attrs = &enum_.attrs;
    let ref_internal_repr_ident = format_ident!("{}RefInternalRepr", enum_ident);
    let ser_helper = format_ident!("{}SerializeHelper", enum_ident);
    let self_ty = enum_.self_ty();
    let (variants_ident, variants_ty, variants_attrs) =
        variants_to_tuple(&self_ty, enum_.variants());
    let (untagged_variants_ident, untagged_variants_ty, untagged_variants_attrs) =
        variants_to_tuple(&self_ty, enum_.untagged_variants());
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

    Ok(quote! {
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
    })
}

pub fn impl_partially_tagged_deserialize(input: &syn::DeriveInput) -> Result<TokenStream> {
    let enum_ = PartiallyTaggedEnum::from_derive_input(input)?;

    let enum_ident = &enum_.ident;
    let enum_attrs = &enum_.attrs;
    let internal_repr_ident = format_ident!("{}InternalRepr", enum_ident);
    let deser_helper = format_ident!("{}DeserializeHelper", enum_ident);
    let no_successful_untagged_variant_match =
        format!("Data did not match any variant of enum {deser_helper}");
    let self_ty = enum_.self_ty();
    let (variants_ident, variants_ty, variants_attrs) =
        variants_to_tuple(&self_ty, enum_.variants());
    let (untagged_variants_ident, untagged_variants_ty, untagged_variants_attrs) =
        variants_to_tuple(&self_ty, enum_.untagged_variants());
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

    Ok(quote! {
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
    })
}
