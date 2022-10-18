#![allow(
    clippy::module_name_repetitions,
    missing_docs,
    clippy::shadow_reuse,
    clippy::str_to_string,
    clippy::arithmetic,
    clippy::std_instead_of_core
)]

use std::{collections::HashMap, ops::Range};

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use proc_macro_error::{abort, abort_call_site, proc_macro_error, OptionExt, ResultExt};
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    spanned::Spanned,
    AttributeArgs, Error as SynError, Ident, ItemEnum, ItemStruct, Lit, LitInt, Meta, NestedMeta,
    Path, Result as SynResult, Token,
};

const VERSION_NUMBER_ARG_NAME: &str = "n";
const VERSIONED_STRUCT_ARG_NAME: &str = "versioned";
const VERSION_FIELD_NAME: &str = "version";
const CONTENT_FIELD_NAME: &str = "content";

/// Used to declare that this struct represents a particular version as a part of the versioned container.
///
/// Adds support for both scale codec and json serialization. To declare only with json support, use [`version_with_json()`], for scale — [`version_with_scale()`].
///
/// ### Arguments
/// - named `n: u8`: what version this particular struct represents.
/// - named `versioned: String`: to which versioned container to link this struct. Versioned containers are created with [`declare_versioned`](`declare_versioned()`).
///
/// ### Examples
/// See [`declare_versioned`](`declare_versioned()`).
#[proc_macro_error]
#[proc_macro_attribute]
pub fn version(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AttributeArgs);
    impl_version(args, item).into()
}

/// See [`version()`] for more information.
#[proc_macro_error]
#[proc_macro_attribute]
pub fn version_with_scale(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AttributeArgs);
    impl_version(args, item).into()
}

/// See [`version()`] for more information.
#[proc_macro_error]
#[proc_macro_attribute]
pub fn version_with_json(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AttributeArgs);
    impl_version(args, item).into()
}

/// Used to generate a versioned container with the given name and given range of supported versions.
///
/// Adds support for both scale codec and json serialization. To declare only with json support, use [`declare_versioned_with_json`](`declare_versioned_with_json()`), for scale — [`declare_versioned_with_scale`](`declare_versioned_with_json()`).
///
/// It's a user responsibility to export `Box` so that this macro works properly
///
/// ### Arguments
/// 1. positional `versioned_enum_name`
/// 2. positional `supported_version_range`
///
/// ### Examples
///
/// ```rust
/// use parity_scale_codec::{Decode, Encode};
/// use serde::{Deserialize, Serialize};
/// use iroha_version_derive::{declare_versioned, version};
/// use iroha_version::json::*;
///
/// declare_versioned!(VersionedMessage 1..2, Debug, Clone, iroha_macro::FromVariant);
///
/// #[version(n = 1, versioned = "VersionedMessage")]
/// #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
/// pub struct Message1;
///
/// let versioned_message: VersionedMessage = Message1.into();
/// let json = versioned_message.to_versioned_json_str().unwrap();
/// let decoded_message = VersionedMessage::from_versioned_json_str(&json).unwrap();
/// match decoded_message {
///    VersionedMessage::V1(message) => {
///        let _message: Message1 = message.into();
///        Ok(())
///    }
///    _ => Err("Unsupported version.".to_string()),
/// }.unwrap();
/// ```
#[proc_macro]
pub fn declare_versioned(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as DeclareVersionedArgs);
    impl_declare_versioned(&args, true, true).into()
}

/// See [`declare_versioned`](`declare_versioned()`) for more information.
#[proc_macro]
pub fn declare_versioned_with_scale(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as DeclareVersionedArgs);
    impl_declare_versioned(&args, true, false).into()
}

/// See [`declare_versioned`](`declare_versioned()`) for more information.
#[proc_macro]
pub fn declare_versioned_with_json(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as DeclareVersionedArgs);
    impl_declare_versioned(&args, false, true).into()
}

fn impl_version(args: Vec<NestedMeta>, item: TokenStream) -> TokenStream2 {
    let (item, struct_name) = if let Ok(item_struct) = syn::parse::<ItemStruct>(item.clone()) {
        (quote!(#item_struct), item_struct.ident)
    } else if let Ok(item_enum) = syn::parse::<ItemEnum>(item) {
        (quote!(#item_enum), item_enum.ident)
    } else {
        abort_call_site!("The attribute should be attached to either struct or enum.");
    };
    let args_map: HashMap<_, _> = args
        .into_iter()
        .filter_map(|meta| {
            if let NestedMeta::Meta(Meta::NameValue(name_value)) = meta {
                Some((
                    name_value
                        .path
                        .get_ident()
                        .expect_or_abort("Expected single identifier for attribute argument key.")
                        .to_string(),
                    name_value.lit,
                ))
            } else {
                None
            }
        })
        .collect();

    for name in args_map.keys() {
        if ![VERSION_NUMBER_ARG_NAME, VERSIONED_STRUCT_ARG_NAME].contains(&name.as_str()) {
            abort!(name.span(), "Unknown field");
        }
    }
    let version_number = args_map
        .get(VERSION_NUMBER_ARG_NAME)
        .expect_or_abort(&format!(
            "No version number argument with name {} found.",
            VERSION_NUMBER_ARG_NAME
        ));
    #[allow(clippy::str_to_string)]
    let version_number: u32 = if let Lit::Int(number) = version_number {
        number
            .base10_parse()
            .expect_or_abort("Failed to parse version number integer literal.")
    } else {
        abort!(
            version_number.span(),
            "Version number argument should have an integer value."
        )
    };
    let versioned_struct_name = args_map
        .get(VERSIONED_STRUCT_ARG_NAME)
        .expect_or_abort(&format!(
            "No versioned struct name argument with name {} found.",
            VERSIONED_STRUCT_ARG_NAME
        ));
    #[allow(clippy::str_to_string)]
    let versioned_struct_name = if let Lit::Str(name) = versioned_struct_name {
        name.value()
    } else {
        abort!(
            version_number.span(),
            "Versioned struct name argument should have a string value."
        )
    };
    let alias_type_name = format_ident!("_{}V{}", versioned_struct_name, version_number);
    quote!(
        /// Autogenerated alias type to link versioned item to its container.
        type #alias_type_name = #struct_name;

        #item
    )
}

struct DeclareVersionedArgs {
    pub enum_name: Ident,
    pub range: Range<u8>,
    pub _comma: Option<Token![,]>,
    pub derive: Punctuated<Path, Token![,]>,
}

impl DeclareVersionedArgs {
    pub fn version_idents(&self) -> Vec<Ident> {
        self.range
            .clone()
            .into_iter()
            .map(|i| Ident::new(&format!("V{}", i), Span::call_site()))
            .collect()
    }

    pub fn version_struct_idents(&self) -> Vec<Ident> {
        self.range
            .clone()
            .into_iter()
            .map(|i| Ident::new(&format!("_{}V{}", self.enum_name, i), Span::call_site()))
            .collect()
    }

    pub fn version_numbers(&self) -> Vec<u8> {
        self.range.clone().into_iter().collect()
    }
}

impl Parse for DeclareVersionedArgs {
    fn parse(input: ParseStream) -> SynResult<Self> {
        let enum_name: Ident = input.parse()?;
        let start_version: LitInt = input.parse()?;
        let start_version: u8 = start_version.base10_parse()?;
        let _ = input.parse::<Token![..]>()?;
        let end_version: LitInt = input.parse()?;
        let end_version: u8 = end_version.base10_parse()?;
        if end_version <= start_version {
            return Err(SynError::new(
                Span::call_site(),
                "The end version should be higher then the start version.",
            ));
        }
        Ok(Self {
            enum_name,
            range: start_version..end_version,
            _comma: input.parse()?,
            derive: Punctuated::parse_terminated(input)?,
        })
    }
}

fn impl_decode_versioned(enum_name: &Ident) -> proc_macro2::TokenStream {
    quote! (
        impl iroha_version::scale::DecodeVersioned for #enum_name {
            fn decode_versioned(input: &[u8]) -> iroha_version::error::Result<Self> {
                use iroha_version::{error::Error, Version, UnsupportedVersion, RawVersioned};
                use parity_scale_codec::Decode;

                if let Some(version) = input.first() {
                    if Self::supported_versions().contains(version) {
                        let mut input = input.clone();
                        Ok(Self::decode(&mut input)?)
                    } else {
                        Err(Error::UnsupportedVersion(Box::new(UnsupportedVersion::new(
                            *version,
                            RawVersioned::ScaleBytes(input.to_vec())
                        ))))
                    }
                } else {
                    Err(Error::NotVersioned)
                }
            }

            fn decode_all_versioned(input: &[u8]) -> iroha_version::error::Result<Self> {
                use iroha_version::{error::Error, Version, UnsupportedVersion, RawVersioned};
                use parity_scale_codec::Decode;

                if let Some(version) = input.first() {
                    if Self::supported_versions().contains(version) {
                        let mut input = input.clone();
                        let obj = Self::decode(&mut input)?;
                        if input.is_empty() {
                            Ok(obj)
                        } else {
                            Err(Error::ExtraBytesLeft(input.len().try_into().expect("`u64` always fit in `usize`")))
                        }
                    } else {
                        Err(Error::UnsupportedVersion(Box::new(UnsupportedVersion::new(
                            *version,
                            RawVersioned::ScaleBytes(input.to_vec())
                        ))))
                    }
                } else {
                    Err(Error::NotVersioned)
                }
            }
        }

        impl iroha_version::scale::EncodeVersioned for #enum_name {
            fn encode_versioned(&self) -> Vec<u8> {
                use parity_scale_codec::Encode;

                self.encode()
            }
        }
    )
}

fn impl_json(enum_name: &Ident, version_field_name: &str) -> proc_macro2::TokenStream {
    quote!(
        impl<'a> iroha_version::json::DeserializeVersioned<'a> for #enum_name {
            fn from_versioned_json_str(input: &str) -> iroha_version::error::Result<Self> {
                use iroha_version::{error::Error, Version, UnsupportedVersion, RawVersioned};
                use serde_json::Value;

                let json: Value = serde_json::from_str(input)?;
                if let Value::Object(map) = json {
                    if let Some(Value::String(version_number)) = map.get(#version_field_name) {
                        let version: u8 = version_number.parse()?;
                        if Self::supported_versions().contains(&version) {
                            Ok(serde_json::from_str(input)?)
                        } else {
                            Err(Error::UnsupportedVersion(Box::new(
                                UnsupportedVersion::new(version, RawVersioned::Json(String::from(input)))
                            )))
                        }
                    } else {
                        Err(Error::NotVersioned)
                    }
                } else {
                    Err(Error::ExpectedJson)
                }
            }
        }

        impl iroha_version::json::SerializeVersioned for #enum_name {
            fn to_versioned_json_str(&self) -> iroha_version::error::Result<String> {
                Ok(serde_json::to_string(self)?)
            }
        }
    )
}

//TODO using this cause linters issue FIXME https://jira.hyperledger.org/browse/IR-1048
fn impl_declare_versioned(
    args: &DeclareVersionedArgs,
    with_scale: bool,
    with_json: bool,
) -> TokenStream2 {
    let version_idents = args.version_idents();
    let version_struct_idents = args.version_struct_idents();
    let version_numbers = args.version_numbers();
    let range_end = args.range.end;
    let range_start = args.range.start;
    let enum_name = &args.enum_name;
    let scale_impl = if with_scale {
        impl_decode_versioned(enum_name)
    } else {
        quote!()
    };
    let scale_derives = if with_scale {
        quote!(parity_scale_codec::Encode, parity_scale_codec::Decode,)
    } else {
        quote!()
    };
    let scale_variant_attributes: Vec<_> = version_numbers
        .iter()
        .map(|version| {
            if with_scale {
                quote!(#[codec(index = #version)])
            } else {
                quote!()
            }
        })
        .collect();
    let version_field_name = VERSION_FIELD_NAME;
    let json_impl = if with_json {
        impl_json(enum_name, version_field_name)
    } else {
        quote!()
    };
    let json_derives = if with_json {
        quote!(serde::Serialize, serde::Deserialize,)
    } else {
        quote!()
    };
    let content_field_name = CONTENT_FIELD_NAME;
    let json_enum_attribute = if with_json {
        quote!(#[serde(tag = #version_field_name, content = #content_field_name)])
    } else {
        quote!()
    };
    let json_variant_attributes: Vec<_> = version_numbers
        .iter()
        .map(|version| {
            if with_json {
                let version = version.to_string();
                quote!(#[serde(rename = #version)])
            } else {
                quote!()
            }
        })
        .collect();
    let derives = &args.derive;

    quote!(
        /// Autogenerated versioned container.
        #[derive(#scale_derives #json_derives #derives)]
        #json_enum_attribute
        pub enum #enum_name {
            #(
                /// This variant represents a particular version.
                #scale_variant_attributes #json_variant_attributes
                #version_idents (#version_struct_idents),
            )*
        }

        impl iroha_version::Version for #enum_name {
            fn version(&self) -> u8 {
                use #enum_name::*;
                match self {
                    #(#version_idents (_) => #version_numbers),* ,
                }
            }

            fn supported_versions() -> core::ops::Range<u8> {
                #range_start .. #range_end
            }
        }

        #scale_impl

        #json_impl
    )
}
