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
        block,
    } = parse_macro_input!(item);

    let fn_name = &sig.ident;
    let ret_type = match &sig.output {
        syn::ReturnType::Type(_, ret_type) => ret_type,
        syn::ReturnType::Default => {
            panic!("Validator entrypoint must have `Verdict` return type");
        }
    };

    let arg: syn::Expr = parse_quote! {
        ::iroha_wasm::query_operation_to_validate()
    };

    quote! {
        mod __private {
            use super::*;

            trait IsVerdict {
                const DUMMY: () = ();
            }

            impl IsVerdict for ::iroha_wasm::data_model::permission::validator::Verdict {}

            // Static check that return type is `Verdict`
            const _: () = <#ret_type as __private::IsVerdict>::DUMMY;
        }


        /// Validator entrypoint
        ///
        /// # Memory safety
        ///
        /// This function transfers the ownership of allocated
        /// [`Verdict`](::iroha_wasm::data_model::permission::validator::Verdict)
        #[no_mangle]
        pub unsafe extern "C" fn _iroha_validator_main(
        ) -> (::iroha_wasm::WasmUsize, ::iroha_wasm::WasmUsize) {
            let verdict = #fn_name(#arg);
            let bytes = <
                ::iroha_wasm::data_model::permission::validator::Verdict as
                ::parity_scale_codec::Encode
            >::encode(verdict);

            let len: ::iroha_wasm::WasmUsize = bytes.len().try_into()
                .dbg_expect("Encoded `Verdict` is to big and it's length can't be \
                             represented as `WasmUsize`");
            let offset = bytes.as_ptr() as ::iroha_wasm::WasmUsize;
            encoded.leak();
            (offset, len)
        }

        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}
