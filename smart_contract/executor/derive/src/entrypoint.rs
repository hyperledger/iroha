//! Module [`executor_entrypoint`](crate::executor_entrypoint) macro implementation

use iroha_macro_utils::Emitter;
use manyhow::emit;
use proc_macro2::TokenStream;
use quote::quote;
use syn::parse_quote;

mod export {
    pub const EXECUTOR_VALIDATE_TRANSACTION: &str = "_iroha_executor_validate_transaction";
    pub const EXECUTOR_VALIDATE_INSTRUCTION: &str = "_iroha_executor_validate_instruction";
    pub const EXECUTOR_VALIDATE_QUERY: &str = "_iroha_executor_validate_query";
    pub const EXECUTOR_MIGRATE: &str = "_iroha_executor_migrate";
}

mod import {
    pub const GET_VALIDATE_TRANSACTION_PAYLOAD: &str = "get_validate_transaction_payload";
    pub const GET_VALIDATE_INSTRUCTION_PAYLOAD: &str = "get_validate_instruction_payload";
    pub const GET_VALIDATE_QUERY_PAYLOAD: &str = "get_validate_query_payload";
}

/// [`executor_entrypoint`](crate::executor_entrypoint()) macro implementation
#[allow(clippy::needless_pass_by_value)]
pub fn impl_entrypoint(emitter: &mut Emitter, item: syn::ItemFn) -> TokenStream {
    macro_rules! match_entrypoints {
        (validate: {
            $($user_entrypoint_name:ident =>
                $generated_entrypoint_name:ident ($query_validating_object_fn_name:ident)),* $(,)?
        }
        other: {
            $($other_user_entrypoint_name:ident => $branch:block),* $(,)?
        }) => {
            match &item.sig.ident {
                $(fn_name if fn_name == stringify!($user_entrypoint_name) => {
                    impl_validate_entrypoint(
                        item,
                        stringify!($user_entrypoint_name),
                        export::$generated_entrypoint_name,
                        import::$query_validating_object_fn_name,
                    )
                })*
                $(fn_name if fn_name == stringify!($other_user_entrypoint_name) => $branch),*
                _ => {
                    emit!(
                        emitter,
                        "Executor entrypoint name must be one of: {:?}",
                        [
                            $(stringify!($user_entrypoint_name),)*
                            $(stringify!($other_user_entrypoint_name),)*
                        ]
                    );
                    return quote!();
                },
            }
        };
    }

    match_entrypoints! {
        validate: {
            validate_transaction => EXECUTOR_VALIDATE_TRANSACTION(GET_VALIDATE_TRANSACTION_PAYLOAD),
            validate_instruction => EXECUTOR_VALIDATE_INSTRUCTION(GET_VALIDATE_INSTRUCTION_PAYLOAD),
            validate_query => EXECUTOR_VALIDATE_QUERY(GET_VALIDATE_QUERY_PAYLOAD),
        }
        other: {
            migrate => { impl_migrate_entrypoint(item) }
        }
    }
}

fn impl_validate_entrypoint(
    fn_item: syn::ItemFn,
    user_entrypoint_name: &'static str,
    generated_entrypoint_name: &'static str,
    get_validation_payload_fn_name: &'static str,
) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        mut block,
    } = fn_item;
    let fn_name = &sig.ident;

    assert!(
        matches!(sig.output, syn::ReturnType::Type(_, _)),
        "Executor `{user_entrypoint_name}` entrypoint must have `Result` return type"
    );

    block.stmts.insert(
        0,
        parse_quote!(
            use ::iroha_executor::smart_contract::{ExecuteOnHost as _};
        ),
    );

    let generated_entrypoint_ident: syn::Ident = syn::parse_str(generated_entrypoint_name)
        .expect("Provided entrypoint name to generate is not a valid Ident, this is a bug");

    let get_validation_payload_fn_ident: syn::Ident =
        syn::parse_str(get_validation_payload_fn_name).expect(
            "Provided function name to query validating object is not a valid Ident, this is a bug",
        );

    quote! {
        /// Executor `validate` entrypoint
        ///
        /// # Memory safety
        ///
        /// This function transfers the ownership of allocated
        /// [`Result`](::iroha_executor::data_model::executor::Result)
        #[no_mangle]
        #[doc(hidden)]
        unsafe extern "C" fn #generated_entrypoint_ident() -> *const u8 {
            let payload = ::iroha_executor::#get_validation_payload_fn_ident();
            let verdict: ::iroha_executor::data_model::executor::Result =
                #fn_name(payload.authority, payload.target, payload.block_height);
            let bytes_box = ::core::mem::ManuallyDrop::new(::iroha_executor::utils::encode_with_length_prefix(&verdict));

            bytes_box.as_ptr()
        }

        // NOTE: Host objects are always passed by value to wasm
        #[allow(clippy::needless_pass_by_value)]
        #(#attrs)*
        #[inline]
        #vis #sig
        #block
    }
}

fn impl_migrate_entrypoint(fn_item: syn::ItemFn) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = fn_item;
    let fn_name = &sig.ident;

    let migrate_fn_name = syn::Ident::new(export::EXECUTOR_MIGRATE, proc_macro2::Span::call_site());

    quote! {
        /// Executor `migrate` entrypoint
        ///
        /// # Memory safety
        ///
        /// This function transfers the ownership of allocated [`Vec`](alloc::vec::Vec).
        #[no_mangle]
        #[doc(hidden)]
        unsafe extern "C" fn #migrate_fn_name() {
            let payload = ::iroha_executor::get_migrate_payload();
            #fn_name(payload.block_height);
        }

        // NOTE: False positive
        #[allow(clippy::unnecessary_wraps)]
        #(#attrs)*
        #[inline]
        #vis #sig
        #block
    }
}
