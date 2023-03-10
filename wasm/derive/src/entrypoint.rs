//! Macro for writing smart contract entrypoint

#![allow(clippy::str_to_string)]

use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{parse_macro_input, parse_quote};

/// [`entrypoint`](crate::entrypoint()) macro implementation
pub fn impl_entrypoint(item: TokenStream) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        mut block,
    } = parse_macro_input!(item);

    if syn::ReturnType::Default != sig.output {
        abort!(sig.output, "Exported function must not have a return type");
    }

    let fn_name = &sig.ident;
    let args = sig.inputs.iter().map(|arg| {
        let syn::FnArg::Typed(syn::PatType {ty, ..}) = arg else {
            abort!(arg, "Receiver types are not supported");
        };

        quote! { <#ty as iroha_wasm::QueryHost>::query() }
    });

    block.stmts.insert(
        0,
        parse_quote!(
            use iroha_wasm::{debug::DebugExpectExt as _, ExecuteOnHost as _};
        ),
    );

    quote! {
        /// Smart contract entrypoint
        #[no_mangle]
        #[doc(hidden)]
        unsafe extern "C" fn _iroha_wasm_main() {
            #fn_name(#(#args),*)
        }

        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}
