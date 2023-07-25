//! Module with [`derive_validate`](crate::derive_validate) macro implementation

use proc_macro2::Span;
use syn::{Attribute, Ident, Path, Type};

use super::*;

/// [`derive_validate`](crate::derive_validate()) macro implementation
pub fn impl_derive_validate(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident;

    let (validate_grant_impl, validate_revoke_impl) = gen_validate_impls(&input.attrs);

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    quote! {
        impl #impl_generics ::iroha_validator::permission::ValidateGrantRevoke for #ident #ty_generics
        #where_clause
        {
            #validate_grant_impl
            #validate_revoke_impl
        }
    }
    .into()
}

/// Enum representing possible attributes.
#[derive(Clone)]
enum ValidateAttribute {
    /// Represents just `validate` attribute.
    General(Type),
    /// Represents `validate_grant` and `validate_revoke` attributes together.
    Separate {
        grant_condition: Type,
        revoke_condition: Type,
    },
}

impl ValidateAttribute {
    fn from_attributes<'attr, A>(attributes: A) -> Self
    where
        A: IntoIterator<Item = &'attr Attribute>,
    {
        let mut general_condition: Option<Type> = None;
        let mut grant_condition: Option<Type> = None;
        let mut revoke_condition: Option<Type> = None;

        let general_path: Path = syn::parse_str("validate").unwrap();
        let grant_path: Path = syn::parse_str("validate_grant").unwrap();
        let revoke_path: Path = syn::parse_str("validate_revoke").unwrap();

        for attribute in attributes {
            let path = &attribute.path;

            // Skip if it's not our attribute
            if path != &general_path && path != &grant_path && path != &revoke_path {
                continue;
            }

            let Some(proc_macro2::TokenTree::Group(group))= attribute.tokens.clone().into_iter().next() else {
                panic!("Expected parentheses group");
            };
            assert!(
                group.delimiter() == proc_macro2::Delimiter::Parenthesis,
                "Expected parentheses"
            );
            let tokens = group.stream().into();

            match path {
                _general if path == &general_path => {
                    assert!(grant_condition.is_none() && revoke_condition.is_none(),
                        "`validate` attribute can't be used with `validate_grant` or `validate_revoke` attributes");
                    assert!(
                        general_condition.is_none(),
                        "`validate` attribute duplication is not allowed"
                    );

                    general_condition.replace(syn::parse(tokens).unwrap());
                }
                _grant if path == &grant_path => {
                    assert!(
                        general_condition.is_none(),
                        "`validate_grant` attribute can't be used with `validate` attribute"
                    );
                    assert!(
                        grant_condition.is_none(),
                        "`validate_grant` attribute duplication is not allowed"
                    );

                    grant_condition.replace(syn::parse(tokens).unwrap());
                }
                _revoke if path == &revoke_path => {
                    assert!(
                        general_condition.is_none(),
                        "`validate_revoke` attribute can't be used with `validate` attribute"
                    );
                    assert!(
                        revoke_condition.is_none(),
                        "`validate_revoke` attribute duplication is not allowed"
                    );

                    revoke_condition.replace(syn::parse(tokens).unwrap());
                }
                path => {
                    panic!(
                        "Unexpected attribute: `{}`. Expected `validate`, `validate_grant` or `validate_revoke`",
                        path.get_ident().map_or_else(|| "<can't display>".to_owned(), ToString::to_string)
                    )
                }
            }
        }

        match (general_condition, grant_condition, revoke_condition) {
            (Some(condition), None, None) => ValidateAttribute::General(condition),
            (None, Some(grant_condition), Some(revoke_condition)) => {
                ValidateAttribute::Separate {
                    grant_condition,
                    revoke_condition,
                }
            }
            (None, Some(_grant_condition), None) => {
                panic!("`validate_grant` attribute should be used together with `validate_revoke` attribute")
            }
            (None, None, Some(_revoke_condition)) => {
                panic!("`validate_revoke` attribute should be used together with `validate_grant` attribute")
            }
            (None, None, None) => panic!("`validate` attribute or combination of `validate_grant` and `validate_revoke` attributes is required"),
            _ => unreachable!(),
        }
    }
}

fn gen_validate_impls(
    attributes: &[Attribute],
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    use ValidateAttribute::*;

    let validate_attribute = ValidateAttribute::from_attributes(attributes);
    match validate_attribute {
        General(pass_condition) => (
            gen_validate_impl(IsiName::Grant, &pass_condition),
            gen_validate_impl(IsiName::Revoke, &pass_condition),
        ),
        Separate {
            grant_condition,
            revoke_condition,
        } => (
            gen_validate_impl(IsiName::Grant, &grant_condition),
            gen_validate_impl(IsiName::Revoke, &revoke_condition),
        ),
    }
}

/// Name of ISI to validate.
#[derive(Copy, Clone)]
enum IsiName {
    Grant,
    Revoke,
}

impl ToString for IsiName {
    fn to_string(&self) -> String {
        match self {
            IsiName::Grant => "grant",
            IsiName::Revoke => "revoke",
        }
        .to_string()
    }
}

fn gen_validate_impl(isi_name: IsiName, pass_condition: &Type) -> proc_macro2::TokenStream {
    use quote::ToTokens;

    let fn_name = Ident::new(
        &format!("validate_{}", isi_name.to_string()),
        Span::call_site(),
    );

    let doc_intro = match isi_name {
        IsiName::Grant => {
            "Validate [`Grant`](::iroha_validator::data_model::prelude::Grant) instruction.\n"
        }
        IsiName::Revoke => {
            "Validate [`Revoke`](::iroha_validator::data_model::prelude::Revoke) instruction.\n"
        }
    };

    let pass_condition_str = pass_condition.to_token_stream().to_string();

    quote! {
        #[doc = #doc_intro]
        #[doc = "\nWrapper around [`"]
        #[doc = #pass_condition_str]
        #[doc = "`]"]
        #[inline]
        fn #fn_name(&self, authority: &::iroha_validator::data_model::account::AccountId) -> ::iroha_validator::data_model::validator::Result {
            let condition = <#pass_condition as ::core::convert::From<&Self>>::from(&self);
            <
                #pass_condition
                as
                ::iroha_validator::permission::PassCondition
            >::validate(&condition, authority)
        }
    }
}
