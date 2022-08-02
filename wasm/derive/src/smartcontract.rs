use super::*;

pub fn impl_entrypoint(_: TokenStream, item: TokenStream) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        mut block,
    } = parse_macro_input!(item);

    verify_function_signature(&sig);
    let fn_name = &sig.ident;

    block.stmts.insert(
        0,
        parse_quote!(
            use iroha_wasm::Execute as _;
        ),
    );

    quote! {
        // NOTE: The size of the `len` parameter is defined by the target architecture
        // which is `wasm32-unknown-unknown` and therefore not dependent by the architecture
        // smart contract is compiled on or the architecture smart contract is run on
        /// Smart contract entry point
        ///
        /// # Safety
        ///
        /// Given pointer and length must comprise a valid memory slice
        #[no_mangle]
        pub unsafe extern "C" fn _iroha_wasm_main(ptr: *const u8, len: usize) {
            #fn_name(
                iroha_wasm::_decode_from_raw::<
                    <iroha_wasm::data_model::account::Account as iroha_wasm::data_model::Identifiable>::Id>
                (ptr, len)
            )
        }

        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}

fn verify_function_signature(sig: &syn::Signature) {
    if syn::ReturnType::Default != sig.output {
        abort!(sig.output, "Exported function must not have a return type");
    }

    if sig.inputs.len() != 1 {
        abort!(
            sig.inputs,
            "Exported function must have one argument of type `AccountId`"
        );
    }
}
