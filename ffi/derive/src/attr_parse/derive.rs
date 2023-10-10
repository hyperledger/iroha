//! This module provides parsing of `#[derive(...)]` attributes

use darling::FromAttributes;
use quote::ToTokens;
use syn2::{punctuated::Punctuated, Attribute, Token};

use super::getset::GetSetDerive;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RustcDerive {
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Clone,
    Copy,
    Hash,
    Default,
    Debug,
}

impl RustcDerive {
    fn try_from_path(path: &syn2::Path) -> Option<Self> {
        let Some(ident) = path.get_ident() else {
            return None;
        };

        match ident.to_string().as_str() {
            "Eq" => Some(Self::Eq),
            "PartialEq" => Some(Self::PartialEq),
            "Ord" => Some(Self::Ord),
            "PartialOrd" => Some(Self::PartialOrd),
            "Clone" => Some(Self::Clone),
            "Copy" => Some(Self::Copy),
            "Hash" => Some(Self::Hash),
            "Default" => Some(Self::Default),
            "Debug" => Some(Self::Debug),
            _ => None,
        }
    }
}

#[allow(variant_size_differences)] // it's not like it's possible to change that..
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Derive {
    Rustc(RustcDerive),
    GetSet(GetSetDerive),
    Other(String),
}

/// Represents a collection of all `#[derive(...)]` attributes placed on the item
///
/// NOTE: strictly speaking, correctly parsing this is impossible, since it requires
/// us to resolve the paths in the attributes, which is not possible in a proc-macro context.
///
/// We just __hope__ that the user refers to the derives by their canonical names (no aliases).
///
/// This, however, will mistakingly thing that `derive_more` derives are actually rustc's built-in ones.
///
/// Care should be taken, and it should be documented in the macro APIs that use this.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeriveAttrs {
    pub derives: Vec<Derive>,
}

impl FromAttributes for DeriveAttrs {
    fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        let mut derives = Vec::new();
        let mut accumulator = darling::error::Accumulator::default();

        for attr in attrs {
            if attr.path().is_ident("derive") {
                let Some(list) = accumulator.handle(attr.meta.require_list().map_err(Into::into))
                else {
                    continue;
                };
                let Some(paths) = accumulator.handle(
                    list.parse_args_with(Punctuated::<syn2::Path, Token![,]>::parse_terminated)
                        .map_err(Into::into),
                ) else {
                    continue;
                };

                for path in paths {
                    // what clippy suggests here is much harder to read
                    #[allow(clippy::option_if_let_else)]
                    let derive = if let Some(derive) = RustcDerive::try_from_path(&path) {
                        Derive::Rustc(derive)
                    } else if let Some(derive) = GetSetDerive::try_from_path(&path) {
                        Derive::GetSet(derive)
                    } else {
                        Derive::Other(path.to_token_stream().to_string())
                    };

                    // Funnily, rust allows the usage of the same derive multiple times
                    // In most cases this will lead to a "Conflicting implementations of trait" errors,
                    //      but technically it's not an error by itself
                    // We do handle the duplicate derives just fine
                    derives.push(derive);
                }
            }
        }

        accumulator.finish_with(Self { derives })
    }
}

#[cfg(test)]
mod test {
    use darling::FromAttributes;
    use proc_macro2::TokenStream;
    use quote::quote;

    use super::{Derive, DeriveAttrs, GetSetDerive, RustcDerive};

    fn parse_derives(attrs: TokenStream) -> darling::Result<DeriveAttrs> {
        let attrs = crate::parse_attributes(attrs);
        DeriveAttrs::from_attributes(&attrs)
    }

    macro_rules! assert_derive_ok {
        ($( #[$meta:meta] )*,
            $expected:expr
        ) => {
            assert_eq!(parse_derives(quote!(
                    $( #[$meta] )*
                )).unwrap(),
                $expected
            )
        };
    }

    #[test]
    fn derive_rustc() {
        assert_derive_ok!(
            #[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Hash, Default, Debug)],
            DeriveAttrs {
                derives: vec![
                    RustcDerive::Eq,
                    RustcDerive::PartialEq,
                    RustcDerive::Ord,
                    RustcDerive::PartialOrd,
                    RustcDerive::Clone,
                    RustcDerive::Copy,
                    RustcDerive::Hash,
                    RustcDerive::Default,
                    RustcDerive::Debug,
                ].into_iter().map(Derive::Rustc).collect(),
            }
        )
    }

    #[test]
    fn derive_getset() {
        assert_derive_ok!(
            #[derive(Getters, Setters, MutGetters, CopyGetters)],
            DeriveAttrs {
                derives: vec![
                    GetSetDerive::Getters,
                    GetSetDerive::Setters,
                    GetSetDerive::MutGetters,
                    GetSetDerive::CopyGetters,
                ].into_iter().map(Derive::GetSet).collect(),
            }
        )
    }

    #[test]
    fn derive_unknown() {
        assert_derive_ok!(
            #[derive(Aboba, Kek)],
            DeriveAttrs {
                derives: vec![
                    "Aboba".to_string(),
                    "Kek".to_string(),
                ].into_iter().map(Derive::Other).collect(),
            }
        )
    }
}
