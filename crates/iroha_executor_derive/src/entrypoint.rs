//! Module [`executor_entrypoint`](crate::executor_entrypoint) macro implementation

use iroha_macro_utils::Emitter;
use manyhow::emit;
use proc_macro2::TokenStream;
use quote::quote;

mod export {
    pub const EXECUTOR_EXECUTE_TRANSACTION: &str = "_iroha_executor_execute_transaction";
    pub const EXECUTOR_EXECUTE_INSTRUCTION: &str = "_iroha_executor_execute_instruction";
    pub const EXECUTOR_VALIDATE_QUERY: &str = "_iroha_executor_validate_query";
    pub const EXECUTOR_MIGRATE_CONTEXT: &str = "_iroha_executor_migrate";
}

mod import {
    pub const DECODE_EXECUTE_TRANSACTION_CONTEXT: &str = "decode_execute_transaction_context";
    pub const DECODE_EXECUTE_INSTRUCTION_CONTEXT: &str = "decode_execute_instruction_context";
    pub const DECODE_VALIDATE_QUERY_CONTEXT: &str = "decode_validate_query_context";
}

/// [`executor_entrypoint`](crate::executor_entrypoint()) macro implementation
#[allow(clippy::needless_pass_by_value)]
pub fn impl_validate_entrypoint(emitter: &mut Emitter, item: syn::ItemFn) -> TokenStream {
    macro_rules! match_entrypoints {
        (validate: {
            $($user_entrypoint_name:ident =>
                $generated_entrypoint_name:ident ($decode_validation_context_fn_name:ident)),* $(,)?
        }) => {
            match &item.sig.ident {
                $(fn_name if fn_name == stringify!($user_entrypoint_name) => {
                    impl_validate_entrypoint_priv(
                        item,
                        stringify!($user_entrypoint_name),
                        export::$generated_entrypoint_name,
                        import::$decode_validation_context_fn_name,
                    )
                })*
                _ => {
                    emit!(
                        emitter,
                        "Executor entrypoint name must be one of: {:?}",
                        [$(stringify!($user_entrypoint_name),)*]
                    );
                    return quote!();
                },
            }
        };
    }

    match_entrypoints! {
        validate: {
            execute_transaction => EXECUTOR_EXECUTE_TRANSACTION(DECODE_EXECUTE_TRANSACTION_CONTEXT),
            execute_instruction => EXECUTOR_EXECUTE_INSTRUCTION(DECODE_EXECUTE_INSTRUCTION_CONTEXT),
            validate_query => EXECUTOR_VALIDATE_QUERY(DECODE_VALIDATE_QUERY_CONTEXT),
        }
    }
}

fn impl_validate_entrypoint_priv(
    fn_item: syn::ItemFn,
    user_entrypoint_name: &'static str,
    generated_entrypoint_name: &'static str,
    decode_validation_context_fn_name: &'static str,
) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = fn_item;
    let fn_name = &sig.ident;

    assert!(
        matches!(sig.output, syn::ReturnType::Type(_, _)),
        "Executor `{user_entrypoint_name}` entrypoint must have `Result` return type"
    );

    let generated_entrypoint_ident: syn::Ident = syn::parse_str(generated_entrypoint_name)
        .expect("Provided entrypoint name to generate is not a valid Ident, this is a bug");

    let decode_validation_context_fn_ident: syn::Ident =
        syn::parse_str(decode_validation_context_fn_name).expect(
            "Provided function name to query validating object is not a valid Ident, this is a bug",
        );

    quote! {
        /// Executor entrypoint
        ///
        /// # Memory safety
        ///
        /// This function transfers the ownership of allocated
        /// [`Result`](::iroha_executor::data_model::executor::Result)
        #[no_mangle]
        #[doc(hidden)]
        unsafe extern "C" fn #generated_entrypoint_ident(context: *const u8) -> *const u8 {
            let host = ::iroha_executor::Iroha;

            let context = ::iroha_executor::utils::#decode_validation_context_fn_ident(context);
            let verdict = #fn_name(context.target, host, context.context);

            let bytes_box = ::core::mem::ManuallyDrop::new(
                ::iroha_executor::utils::encode_with_length_prefix(&verdict)
            );

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

pub fn impl_migrate_entrypoint(fn_item: syn::ItemFn) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = fn_item;
    let fn_name = &sig.ident;

    let migrate_fn_name = syn::Ident::new(
        export::EXECUTOR_MIGRATE_CONTEXT,
        proc_macro2::Span::call_site(),
    );

    quote! {
        iroha_executor::utils::register_getrandom_err_callback!();

        /// Executor `migrate` entrypoint
        ///
        /// # Memory safety
        ///
        /// This function transfers the ownership of allocated [`Vec`](alloc::vec::Vec).
        #[no_mangle]
        #[doc(hidden)]
        unsafe extern "C" fn #migrate_fn_name(context: *const u8) {
            let host = ::iroha_executor::smart_contract::Iroha;
            let context = ::iroha_executor::utils::decode_migrate_context(context);
            #fn_name(host, context);
        }

        // NOTE: False positive
        #[allow(clippy::unnecessary_wraps)]
        #(#attrs)*
        #[inline]
        #vis #sig
        #block
    }
}
