//! Module [`validator_entrypoint`](crate::validator_entrypoint) macro implementation

use proc_macro_error::abort;

use super::*;

pub fn impl_entrypoint(item: TokenStream) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        mut block,
    } = parse_macro_input!(item);

    if !matches!(sig.output, syn::ReturnType::Type(_, _)) {
        abort!(sig.output, "Validator must have `Verdict` return type");
    }

    let fn_name = &sig.ident;
    let args = sig.inputs.iter().map(|arg| {
        let syn::FnArg::Typed(syn::PatType {ty, ..}) = arg else {
            abort!(arg, "Receiver types are not supported");
        };

        quote! { <#ty as iroha_validator::iroha_wasm::QueryHost>::query() }
    });

    block.stmts.insert(
        0,
        parse_quote!(
            use ::iroha_validator::iroha_wasm::ExecuteOnHost as _;
        ),
    );

    quote! {
        /// Validator entrypoint
        ///
        /// # Memory safety
        ///
        /// This function transfers the ownership of allocated
        /// [`Verdict`](::iroha_validator::iroha_wasm::data_model::permission::validator::Verdict)
        #[no_mangle]
        #[doc(hidden)]
        unsafe extern "C" fn _iroha_wasm_main() -> *const u8 {
            let verdict: ::iroha_validator::iroha_wasm::data_model::permission::validator::Verdict = #fn_name(#(#args),*);
            let bytes_box = ::core::mem::ManuallyDrop::new(::iroha_validator::iroha_wasm::encode_with_length_prefix(&verdict));

            bytes_box.as_ptr()
        }

        #(#attrs)*
        #vis #sig
        #block
    }.into()
}
