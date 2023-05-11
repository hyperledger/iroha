//! Module [`validator_entrypoint`](crate::validator_entrypoint) macro implementation

use super::*;

mod kw {
    pub mod param_types {
        syn::custom_keyword!(authority);
        syn::custom_keyword!(operation);
    }
}

/// Enum representing possible attributes for [`entrypoint`] macro
enum Attr {
    /// List of parameters
    Params(iroha_derive_primitives::params::ParamsAttr<ParamType>),
}

impl syn::parse::Parse for Attr {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        Ok(Attr::Params(input.parse()?))
    }
}

/// Type of smart contract entrypoint function parameter.
///
/// *Type* here means not just *Rust* type but also a purpose of a parameter.
/// So that it uses [`Authority`](ParamType::Authority) instead of [`AccountId`].
#[derive(PartialEq, Eq)]
enum ParamType {
    Authority,
    Operation,
}

impl syn::parse::Parse for ParamType {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        use kw::param_types::*;

        iroha_derive_primitives::parse_keywords!(input,
            authority => ParamType::Authority,
            operation => ParamType::Operation,
        )
    }
}

impl iroha_derive_primitives::params::ConstructArg for ParamType {
    fn construct_arg(&self) -> syn::Expr {
        match self {
            ParamType::Authority => {
                parse_quote! {
                    ::iroha_validator::iroha_wasm::query_authority()
                }
            }
            ParamType::Operation => {
                parse_quote! {{
                    ::iroha_validator::iroha_wasm::query_operation_to_validate()
                }}
            }
        }
    }
}

/// [`validator_entrypoint`](crate::validator_entrypoint()) macro implementation
#[allow(clippy::needless_pass_by_value)]
pub fn impl_entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        mut block,
    } = parse_macro_input!(item);

    let fn_name = &sig.ident;
    assert!(
        matches!(sig.output, syn::ReturnType::Type(_, _)),
        "Validator entrypoint must have `Verdict` return type"
    );

    let args = match syn::parse_macro_input!(attr as Attr) {
        Attr::Params(params_attr) => {
            params_attr
                .types()
                .find(|param_type| *param_type == &ParamType::Operation)
                .expect(
                    "Validator entrypoint macro attribute must have parameter of `operation` type",
                );

            params_attr.construct_args()
        }
    };

    block.stmts.insert(
        0,
        parse_quote!(
            use ::iroha_validator::iroha_wasm::{ExecuteOnHost as _, QueryHost as _};
        ),
    );

    quote! {
        /// Validator entrypoint
        ///
        /// # Memory safety
        ///
        /// This function transfers the ownership of allocated
        /// [`Verdict`](::iroha_validator::iroha_wasm::data_model::validator::Verdict)
        #[no_mangle]
        #[doc(hidden)]
        unsafe extern "C" fn _iroha_wasm_main() -> *const u8 {
            let verdict: ::iroha_validator::iroha_wasm::data_model::validator::Verdict = #fn_name(#args);
            let bytes_box = ::core::mem::ManuallyDrop::new(::iroha_validator::iroha_wasm::encode_with_length_prefix(&verdict));

            bytes_box.as_ptr()
        }

        // NOTE: Host objects are allways passed by value to wasm
        #[allow(clippy::needless_pass_by_value)]
        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}
