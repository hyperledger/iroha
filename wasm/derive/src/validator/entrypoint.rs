//! Module [`validator_entrypoint`](crate::validator_entrypoint) macro implementation

use super::*;

mod kw {
    pub mod param_types {
        syn::custom_keyword!(authority);
        syn::custom_keyword!(transaction);
        syn::custom_keyword!(instruction);
        syn::custom_keyword!(query);
        syn::custom_keyword!(expression);
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
/// So that it uses [`Authority`](ParamType::Authority) instead of `account::Id`.
#[derive(PartialEq, Eq)]
enum ParamType {
    Authority,
    Transaction,
    Instruction,
    Query,
    Expression,
}

impl syn::parse::Parse for ParamType {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        use kw::param_types::*;

        iroha_derive_primitives::parse_keywords!(input,
            authority => ParamType::Authority,
            transaction => ParamType::Transaction,
            instruction => ParamType::Instruction,
            query => ParamType::Query,
            expression => ParamType::Expression,
        )
    }
}

impl ParamType {
    fn construct_operation_arg(operation_type: &syn::Type) -> syn::Expr {
        parse_quote! {{
            use ::alloc::format;

            let needs_permission = ::iroha_wasm::query_operation_to_validate();
            ::iroha_wasm::debug::DebugExpectExt::dbg_expect(
                <::iroha_wasm::data_model::prelude::#operation_type as
                    ::core::convert::TryFrom<::iroha_wasm::data_model::permission::validator::NeedsPermissionBox>>::try_from(needs_permission),
                    &format!("Failed to convert `NeedsPermissionBox` to `{}`. Have you set right permission validator type?", stringify!(#operation_type))
            )
        }}
    }
}

impl iroha_derive_primitives::params::ConstructArg for ParamType {
    fn construct_arg(&self) -> syn::Expr {
        match self {
            ParamType::Authority => {
                parse_quote! {
                    ::iroha_wasm::query_authority()
                }
            }
            ParamType::Transaction => {
                Self::construct_operation_arg(&parse_quote!(SignedTransaction))
            }
            ParamType::Instruction => Self::construct_operation_arg(&parse_quote!(Instruction)),
            ParamType::Query => Self::construct_operation_arg(&parse_quote!(QueryBox)),
            ParamType::Expression => Self::construct_operation_arg(&parse_quote!(Expression)),
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
            let operation_param_count = params_attr
                .types()
                .filter(|param_type| *param_type != &ParamType::Authority)
                .count();
            assert!(
                operation_param_count == 1,
                "Validator entrypoint macro attribute must have exactly one parameter \
                of some operation type: `transaction`, `instruction`, `query` or `expression`"
            );

            params_attr.construct_args()
        }
    };

    block.stmts.insert(
        0,
        parse_quote!(
            use ::iroha_wasm::{debug::DebugExpectExt as _, EvaluateOnHost as _};
        ),
    );

    quote! {
        /// Validator entrypoint
        ///
        /// # Memory safety
        ///
        /// This function transfers the ownership of allocated
        /// [`Verdict`](::iroha_wasm::data_model::permission::validator::Verdict)
        #[no_mangle]
        #[doc(hidden)]
        unsafe extern "C" fn _iroha_wasm_main() -> *const u8 {
            let verdict: ::iroha_wasm::data_model::permission::validator::Verdict = #fn_name(#args);
            let bytes_box = ::core::mem::ManuallyDrop::new(::iroha_wasm::encode_with_length_prefix(&verdict));

            bytes_box.as_ptr()
        }

        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}
