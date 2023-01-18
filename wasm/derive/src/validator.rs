//! Macro for writing validator entrypoint

#![allow(clippy::panic)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, DeriveInput};

pub mod entrypoint {
    //! Module [`crate::validator_entrypoint`] macro implementation

    use super::*;

    mod kw {
        pub mod param_types {
            syn::custom_keyword!(authority);
            syn::custom_keyword!(transaction);
            syn::custom_keyword!(instruction);
            syn::custom_keyword!(query);
            syn::custom_keyword!(expression);
        }
    }

    /// Enum representing possible attributes for [`entrypoint`] macro
    enum Attr {
        /// List of parameters
        Params(crate::params::ParamsAttr<ParamType>),
    }

    impl syn::parse::Parse for Attr {
        fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
            Ok(Attr::Params(input.parse()?))
        }
    }

    /// Type of smart contract entrypoint function parameter.
    ///
    /// *Type* here means not just *Rust* type but also a purpose of a parameter.
    /// So that it uses [`Authority`](ParamType::Authority) instead of `account::Id`.
    #[derive(PartialEq, Eq)]
    enum ParamType {
        Authority,
        Transaction,
        Instruction,
        Query,
        Expression,
    }

    impl syn::parse::Parse for ParamType {
        fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
            use kw::param_types::*;

            crate::parse_keywords!(input,
                authority => ParamType::Authority,
                transaction => ParamType::Transaction,
                instruction => ParamType::Instruction,
                query => ParamType::Query,
                expression => ParamType::Expression,
            )
        }
    }

    impl ParamType {
        fn construct_operation_arg(operation_type: &syn::Type) -> syn::Expr {
            parse_quote! {{
                use ::iroha_wasm::debug::DebugExpectExt as _;
                use ::alloc::format;

                let needs_permission = ::iroha_wasm::query_operation_to_validate();
                <
                    ::iroha_wasm::data_model::prelude::#operation_type
                    as ::core::convert::TryFrom<
                        ::iroha_wasm::data_model::permission::validator::NeedsPermissionBox
                    >
                >::try_from(needs_permission)
                    .dbg_expect(&format!(
                        "Failed to convert `NeedsPermissionBox` to `{}`. \
            Have you set right permission validator type?",
                        stringify!(#operation_type)
                    ))
            }}
        }
    }

    impl crate::params::ConstructArg for ParamType {
        fn construct_arg(&self) -> syn::Expr {
            match self {
                ParamType::Authority => {
                    parse_quote! {
                        ::iroha_wasm::query_authority()
                    }
                }
                ParamType::Transaction => {
                    Self::construct_operation_arg(&parse_quote!(SignedTransaction))
                }
                ParamType::Instruction => Self::construct_operation_arg(&parse_quote!(Instruction)),
                ParamType::Query => Self::construct_operation_arg(&parse_quote!(QueryBox)),
                ParamType::Expression => Self::construct_operation_arg(&parse_quote!(Expression)),
            }
        }
    }

    /// [`validator_entrypoint`](crate::validator_entrypoint()) macro implementation
    #[allow(clippy::needless_pass_by_value)]
    pub fn impl_entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
        let syn::ItemFn {
            attrs,
            vis,
            sig,
            mut block,
        } = parse_macro_input!(item);

        let fn_name = &sig.ident;
        assert!(
            matches!(sig.output, syn::ReturnType::Type(_, _)),
            "Validator entrypoint must have `Verdict` return type"
        );

        let args = match syn::parse_macro_input!(attr as Attr) {
            Attr::Params(params_attr) => {
                let operation_param_count = params_attr
                    .types()
                    .filter(|param_type| *param_type != &ParamType::Authority)
                    .count();
                assert!(
                    operation_param_count == 1,
                    "Validator entrypoint macro attribute must have exactly one parameter \
                    of some operation type: `transaction`, `instruction`, `query` or `expression`"
                );

                params_attr.construct_args()
            }
        };

        block.stmts.insert(
            0,
            parse_quote!(
                use ::iroha_wasm::Execute as _;
            ),
        );

        quote! {
            /// Validator entrypoint
            ///
            /// # Memory safety
            ///
            /// This function transfers the ownership of allocated
            /// [`Verdict`](::iroha_wasm::data_model::permission::validator::Verdict)
            #[no_mangle]
            pub unsafe extern "C" fn _iroha_validator_main()
                -> *const u8
            {
                use ::iroha_wasm::DebugExpectExt as _;

                let verdict: ::iroha_wasm::data_model::permission::validator::Verdict = #fn_name(#args);
                let bytes_box = ::core::mem::ManuallyDrop::new(
                    ::iroha_wasm::encode_with_length_prefix(&verdict).into_boxed_slice()
                );

                bytes_box.as_ptr()
            }

            #(#attrs)*
            #vis #sig
            #block
        }
        .into()
    }
}

pub mod token {
    //! Module with [`derive_token`](crate::derive_token()) macro implementation

    use super::*;

    /// [`derive_token`](crate::derive_token()) macro implementation
    pub fn impl_derive_token(input: TokenStream) -> TokenStream {
        let input = parse_macro_input!(input as DeriveInput);
        let ident = input.ident;

        let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

        let permission_token_conversion_code = permission_token_conversion(&ident, &input.data);

        quote! {
            impl #impl_generics ::iroha_wasm::validator::traits::Token for #ident #ty_generics
            #where_clause
            {
                fn is_owned_by(
                    &self,
                    account_id: &<
                        ::iroha_wasm::data_model::prelude::Account
                        as
                        ::iroha_wasm::data_model::prelude::Identifiable
                    >::Id
                ) -> bool {
                    use ::iroha_wasm::Execute as _;

                    let permission_token = #permission_token_conversion_code;

                    ::iroha_wasm::data_model::prelude::QueryBox::DoesAccountHavePermissionToken(
                        ::iroha_wasm::data_model::prelude::DoesAccountHavePermissionToken {
                            account_id: account_id.clone().into(),
                            permission_token,
                        }
                    )
                    .execute()
                    .try_into()
                    .dbg_expect("Failed to convert `DoesAccountHavePermission` query result into `bool`")
                }
            }
        }
        .into()
    }

    #[allow(clippy::arithmetic_side_effects)] // Triggers on quote! side
    fn permission_token_conversion(
        ident: &syn::Ident,
        data: &syn::Data,
    ) -> proc_macro2::TokenStream {
        use convert_case::{Case, Casing as _};

        let syn::Data::Struct(syn::DataStruct { fields, .. }) = data else {
            panic!("`Token` can be derived only for structs");
        };
        let syn::Fields::Named(syn::FieldsNamed { named, .. }) = fields else {
            panic!("`Token` can be derived only for structs with named fields");
        };

        let definition_id = proc_macro2::Literal::string(&ident.to_string().to_case(Case::Snake));
        let params = named.iter().map(|field| {
            let field_ident = field.ident.as_ref().expect("Field must have an identifier");
            let field_literal = proc_macro2::Literal::string(&field_ident.to_string());
            quote! {(
                ::iroha_wasm::parse!(#field_literal
                    as ::iroha_wasm::data_model::prelude::Name),
                self.#field_ident.clone().into()
            )}
        });

        quote! {
            ::iroha_wasm::data_model::permission::Token::new(::iroha_wasm::parse!(
                #definition_id as <
                    ::iroha_wasm::data_model::permission::token::Definition
                    as
                    ::iroha_wasm::data_model::prelude::Identifiable
                >::Id
            ))
            .with_params([
                #(#params),*
            ])
        }
    }
}
