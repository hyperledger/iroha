//! Crate with various derive macros

use darling::FromDeriveInput as _;

mod from_variant;
mod serde_where;

use iroha_macro_utils::Emitter;
use manyhow::{manyhow, Result};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens as _};

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

/// `#[serde_where]` attribute is a `derive-where`-like macro for serde, useful when associated types are used.
///
/// It allows you to specify where bounds for `Serialize` and `Deserialize` traits with a more concise syntax.
///
/// ```rust
/// use iroha_derive::serde_where;
/// use serde::{Deserialize, Serialize};
///
/// trait Trait {
///     type Assoc;
/// }
///
/// #[serde_where(T::Assoc)]
/// #[derive(Serialize, Deserialize)]
/// struct Type<T: Trait> {
///     field: T::Assoc,
/// }
/// ```
#[manyhow]
#[proc_macro_attribute]
pub fn serde_where(arguments: TokenStream, item: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(derive_input) = emitter.handle(syn::parse2::<syn::DeriveInput>(item.clone())) else {
        // pass the input as-is, even if it's not a valid derive input
        return emitter.finish_token_stream_with(item);
    };
    let Some(arguments) =
        emitter.handle(syn::parse2::<serde_where::SerdeWhereArguments>(arguments))
    else {
        // if we can't parse the arguments - pass the input as is
        return emitter.finish_token_stream_with(derive_input.into_token_stream());
    };

    let result = serde_where::impl_serde_where(&mut emitter, arguments, derive_input);

    emitter.finish_token_stream_with(result)
}
