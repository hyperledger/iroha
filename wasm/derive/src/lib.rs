//! Macros for writing smartcontracts

#![allow(clippy::str_to_string)]

use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, parse_quote, ItemFn, Path, ReturnType, Signature, Type};

/// Used to annotate user-defined function which starts the execution of smartcontract
#[proc_macro_error]
#[proc_macro_attribute]
pub fn iroha_wasm(_: TokenStream, item: TokenStream) -> TokenStream {
    let ItemFn {
        attrs,
        vis,
        sig,
        mut block,
    }: ItemFn = parse_macro_input!(item as ItemFn);

    verify_function_signature(&sig);
    let fn_name = &sig.ident;

    block.stmts.insert(
        0,
        parse_quote!(
            use iroha_wasm::Execute as _;
        ),
    );

    quote! {
        #[no_mangle]
        unsafe extern "C" fn _iroha_wasm_main(ptr: u32, len: u32) {
            #fn_name(iroha_wasm::_decode_from_raw::<AccountId>(ptr, len))
        }

        #[allow(clippy::needless_pass_by_value)]
        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}

fn verify_function_signature(sig: &Signature) -> bool {
    if ReturnType::Default != sig.output {
        abort!(sig.output, "Exported function must not have a return type");
    }

    if sig.inputs.len() != 1 {
        abort!(
            sig.inputs,
            "Exported function must have exactly 1 input argument of type `AccountId`"
        );
    }

    if let Some(syn::FnArg::Typed(pat)) = sig.inputs.iter().next() {
        if let syn::Type::Reference(ty) = &*pat.ty {
            return type_is_account_id(&ty.elem);
        }
    }

    false
}

fn type_is_account_id(account_id_ty: &Type) -> bool {
    const ACCOUNT_ID_IDENT: &str = "AccountId";

    if let Type::Path(path) = account_id_ty {
        let Path { segments, .. } = &path.path;

        if let Some(type_name) = segments.iter().last().map(|ty| &ty.ident) {
            return *type_name == ACCOUNT_ID_IDENT;
        }
    }

    false
}
