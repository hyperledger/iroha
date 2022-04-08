//! Crate with various derive macros

#![allow(clippy::restriction)]

use proc_macro::TokenStream;
use quote::quote;

mod dump_decoded;
mod from_variant;

/// [`FromVariant`] is used for implementing `From<Variant> for Enum`
/// and `TryFrom<Enum> for Variant`.
///
/// ```rust
/// use iroha_derive::FromVariant;
///
/// #[derive(FromVariant)]
/// enum Obj {
///     Uint(u32),
///     Int(i32),
///     String(String),
///     // You can also skip implementing `From`
///     Vec(#[skip_from] Vec<Obj>),
/// }
///
/// // For example, to avoid:
/// impl<T: Into<Obj>> From<Vec<T>> for Obj {
///     fn from(vec: Vec<T>) -> Self {
///         # stringify!(
///         ...
///         # );
///         # todo!()
///     }
/// }
/// ```
#[proc_macro_derive(FromVariant, attributes(skip_from, skip_try_from))]
pub fn from_variant_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input Token Stream.");
    from_variant::impl_from_variant(&ast)
}

/// [`DumpDecoded`] is used for `parity_sale_decoder` tool
/// to achieve searching for type by string
///
/// This macro will produce code only if `dump_decoded` feature is enabled
#[proc_macro_derive(DumpDecoded, attributes(dump_decoded))]
pub fn dump_decoded_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input Token Stream.");
    dump_decoded::impl_dump_decoded(&ast)
}

/// Generate static map (`String` -> `fn to decode and dump`)
/// for `parity_sale_decoder` tool.
///
/// This macro highly depends on [`dump_decoded_derive()`] macro
/// which should be executed first.
/// Since Rust doesn't guarantee macro expansion order this macro can fail
///
/// This macro will produce code only if `dump_decoded` feature is enabled
#[proc_macro]
pub fn generate_dump_decoded_map(_input: TokenStream) -> TokenStream {
    dump_decoded::impl_generate_dump_decoded_map()
}

/// Get static map (`String` -> `fn to decode and dump`).
/// It's the only legal way to access generated map!
/// Should be used only by `parity_sale_decoder` tool.
///
/// Will generate valid code only if `dump_decoded` feature is enabled
#[proc_macro]
pub fn get_dump_decoded_map(_input: TokenStream) -> TokenStream {
    dump_decoded::impl_get_dump_decoded_map()
}
