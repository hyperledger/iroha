//! Crate with various derive macros

#![allow(clippy::restriction)]

use proc_macro::TokenStream;
use quote::quote;

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
