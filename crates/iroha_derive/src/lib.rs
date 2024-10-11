//! Crate with various derive macros

use darling::FromDeriveInput as _;

mod from_variant;

use manyhow::{manyhow, Result};
use proc_macro2::TokenStream;
use quote::quote;

/// Helper macro to expand FFI functions
#[manyhow]
#[proc_macro_attribute]
pub fn ffi_impl_opaque(_: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let item: syn::ItemImpl = syn::parse2(item)?;

    Ok(quote! {
        #[cfg_attr(
            all(feature = "ffi_export", not(feature = "ffi_import")),
            iroha_ffi::ffi_export
        )]
        #[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
        #item
    })
}

/// [`FromVariant`] is used for implementing `From<Variant> for Enum`
/// and `TryFrom<Enum> for Variant`.
///
/// ```rust
/// use iroha_derive::FromVariant;
///
/// trait MyTrait {}
///
/// #[derive(FromVariant)]
/// enum Obj {
///     Uint(u32),
///     Int(i32),
///     String(String),
///     // You can skip implementing `From`
///     Vec(#[skip_from] Vec<Obj>),
///     // You can also skip implementing `From` for item inside containers such as `Box`
///     Box(#[skip_container] Box<dyn MyTrait>)
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
#[manyhow]
#[proc_macro_derive(FromVariant, attributes(skip_from, skip_try_from, skip_container))]
pub fn from_variant_derive(input: TokenStream) -> Result<TokenStream> {
    let ast = syn::parse2(input)?;
    let ast = from_variant::FromVariantInput::from_derive_input(&ast)?;
    Ok(from_variant::impl_from_variant(&ast))
}
