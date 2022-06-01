//! Macros for writing smartcontracts

#![allow(clippy::str_to_string)]

use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, parse_quote, ItemFn, Path, ReturnType, Signature, Type};

/// Used to annotate user-defined function which starts the execution of smartcontract
#[proc_macro_error]
#[proc_macro_attribute]
pub fn entrypoint(_: TokenStream, item: TokenStream) -> TokenStream {
    let ItemFn {
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
            #fn_name(iroha_wasm::_decode_from_raw::<<Account as Identifiable>::Id>(ptr, len))
        }

        #[allow(clippy::needless_pass_by_value)]
        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}

fn verify_function_signature(sig: &Signature) {
    if ReturnType::Default != sig.output {
        abort!(sig.output, "Exported function must not have a return type");
    }

    if sig.inputs.len() != 1 {
        abort!(
            sig.inputs,
            "Exported function must have exactly 1 input argument of type `Account::Id`"
        );
    }

    if let Some(syn::FnArg::Typed(pat)) = sig.inputs.iter().next() {
        if !type_is_account_id(&pat.ty) {
            abort!(
                pat.ty,
                "Argument to the exported function must be of the `Account::Id` type"
            );
        }
    }
}

fn type_is_account_id(account_id_ty: &Type) -> bool {
    if *account_id_ty == parse_quote!(<Account as Identifiable>::Id) {
        return true;
    }

    if let Type::Path(path) = account_id_ty {
        let Path { segments, .. } = &path.path;

        if let Some(type_name) = segments.last().map(|ty| &ty.ident) {
            return *type_name == "AccountId";
        }
    }

    false
}
