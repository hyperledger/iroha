use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, FnArg, ImplItem, ItemImpl, ReturnType, Visibility};

#[proc_macro_attribute]
pub fn iroha_wasm_bindgen(attr: TokenStream, item: TokenStream) -> TokenStream {
    let ItemImpl {
        attrs,
        unsafety,
        generics,
        trait_,
        self_ty,
        items,
        ..
    } = parse_macro_input!(item);

    if unsafety.is_some() {
        // TODO: Why not?
        panic!("Unsafe methods not allowed");
    }

    if !generics.params.is_empty() {
        // TODO: Can I not?
        panic!("Can't have generics on impl in FFI");
    }

    if trait_.is_some() {
        // TODO: Are they?
        panic!("Only inherent methods are allowed");
    }

    let wasm_items = items.iter().map(|item| {
        if let ImplItem::Method(method) = item {
            match method.vis {
                // Expose only public methods
                Visibility::Public(_) => {}
                _ => return,
            }

            let block = method.block;
            let sig = &method.sig;
            let fn_name = sig.ident;
            let ret_ty = sig.output;
            let fn_args = sig.inputs;

            if !sig.generics.params.is_empty() {
                panic!("Can't have generics on methods in FFI");
            }

            for arg in &sig.inputs {
                match arg {
                    FnArg::Receiver(self_arg) => {}
                    FnArg::Typed(arg) => {}
                }
            }

            let ptr_mutability =
            let convert_args = fn_args.iter().map(|arg| {
            }).collect();

            //match &sig.output {
            //    ReturnType::Default => {}
            //    ReturnType::Type(_, ret_ty) => {}
            //}

            parse_quote! {
                pub fn #fn_name(self_: #ptr_mut #self_ty, #( #fn_args )*) -> #ret_ty {
                    #( #convert_args )*
                    let res = #block;
                    res.into_wasm()
                }
            }
        }
    }).collect();

    quote! {
        #( #attrs )*
        impl #self_ty {
            #( #items )*
        }

        #( #wasm_items )*
    }
    .into()
}
