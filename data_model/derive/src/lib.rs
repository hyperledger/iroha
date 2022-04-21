#![allow(clippy::str_to_string, missing_docs)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, visit::Visit, ItemImpl};

use crate::ffi::ImplDescriptor;

mod ffi;

#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn ffi_bindgen(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_impl: ItemImpl = parse_macro_input!(item);
    let mut impl_descriptor = ImplDescriptor::new();

    impl_descriptor.visit_item_impl(&item_impl);
    let ffi_fns = impl_descriptor.fns;

    quote! {
        #item_impl

        #( #ffi_fns )*
    }
    .into()
}

//#[cfg(test)]
//mod tests {
//    use super::*;
//
//    #[test]
//    fn valid_self_type_name() {
//        let self_ty = parse_quote! {"white"};
//        let fn_name = parse_quote! {"shark"};
//
//        assert_eq!(get_self_type_name(&self_ty_name, &fn_name), "white_shark");
//    }
//
//    #[test]
//    fn valid_ffi_fn_name() {
//        let self_ty_name: Ident = parse_quote! {white};
//        let fn_name: Ident = parse_quote! {shark};
//
//        assert_eq!(get_ffi_fn_name(&self_ty_name, &fn_name), "white_shark");
//    }
//
//    #[test]
//    fn valid_ret_type_name() {
//        let self_ty_name = parse_quote! {white};
//        let fn_name = parse_quote! {get_shark};
//
//        // TODO: Add more, there should be other versions
//        assert_eq!(get_ret_type_name(&self_ty_name, &fn_name), "shark");
//    }
//}
