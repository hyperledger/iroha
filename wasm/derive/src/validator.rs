//! Macro for writing validator entrypoint

#![allow(clippy::panic)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote};

/// [`validator_entrypoint`](crate::validator_entrypoint()) macro implementation
#[allow(clippy::needless_pass_by_value)]
pub fn impl_entrypoint(_attr: TokenStream, item: TokenStream) -> TokenStream {
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

    let arg: syn::Expr = parse_quote! {{
        let needs_permission: ::iroha_wasm::data_model::permission::validator::NeedsPermissionBox =
            ::iroha_wasm::query_operation_to_validate();
        ::core::convert::TryInto::try_into(needs_permission)
            .dbg_expect("Failed to convert `NeedsPermissionBox` to the concrete operation")
    }};

    block.stmts.insert(
        0,
        parse_quote!(
            use ::iroha_wasm::Execute as _;
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
        pub unsafe extern "C" fn _iroha_validator_main()
            -> *const u8
        {
            use ::iroha_wasm::DebugExpectExt as _;

            let verdict: ::iroha_wasm::data_model::permission::validator::Verdict = #fn_name(#arg);
            let bytes_box = ::core::mem::ManuallyDrop::new(
                ::iroha_wasm::encode_with_length_prefix(&verdict).into_boxed_slice()
            );

            bytes_box.as_ptr()
        }

        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}
