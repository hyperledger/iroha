//! Module with [`derive_validate`](crate::derive_validate) macro implementation

use darling::FromAttributes;
use manyhow::Result;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn2::{Attribute, Ident, Type};

/// [`derive_validate`](crate::derive_validate()) macro implementation
pub fn impl_derive_validate_grant_revoke(input: &syn2::DeriveInput) -> Result<TokenStream> {
    let ident = &input.ident;

    let (validate_grant_impl, validate_revoke_impl) = gen_validate_impls(&input.attrs)?;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics ::iroha_executor::permission::ValidateGrantRevoke for #ident #ty_generics
        #where_clause
        {
            #validate_grant_impl
            #validate_revoke_impl
        }
    })
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

impl FromAttributes for ValidateAttribute {
    // NOTE: we use `Option::or` to select the first specified condition in case of duplicates
    // but we still _want_ to validate that each attribute parses successfully
    // this is to ensure that we provide the user with as much validation as possible, instead of bailing out early
    // `Option::or_else` would NOT work here, as it would not validate conditions after the first valid one
    #[allow(clippy::or_fun_call, clippy::too_many_lines)]
    fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        let mut accumulator = darling::error::Accumulator::default();

        let mut general_condition: Option<Type> = None;
        let mut grant_condition: Option<Type> = None;
        let mut revoke_condition: Option<Type> = None;

        for attr in attrs {
            let path = attr.path();
            if !path.is_ident("validate")
                && !path.is_ident("validate_grant")
                && !path.is_ident("validate_revoke")
            {
                continue;
            }

            let Some(list) =
                accumulator.handle(attr.meta.require_list().map_err(darling::Error::from))
            else {
                continue;
            };
            let tokens = &list.tokens;

            if path.is_ident("validate") {
                if grant_condition.is_some() || revoke_condition.is_some() {
                    accumulator.push(darling::Error::custom(
                        "`validate` attribute can't be used with `validate_grant` or `validate_revoke` attributes"
                    ).with_span(&attr))
                }
                if general_condition.is_some() {
                    accumulator.push(
                        darling::Error::custom("`validate` attribute duplication is not allowed")
                            .with_span(&attr),
                    )
                }

                general_condition = general_condition
                    .or(accumulator
                        .handle(syn2::parse2(tokens.clone()).map_err(darling::Error::from)));
            } else if path.is_ident("grant") {
                if general_condition.is_some() {
                    accumulator.push(
                        darling::Error::custom(
                            "`validate_grant` attribute can't be used with `validate` attribute",
                        )
                        .with_span(&attr),
                    )
                }
                if grant_condition.is_some() {
                    accumulator.push(
                        darling::Error::custom(
                            "`validate_grant` attribute duplication is not allowed",
                        )
                        .with_span(&attr),
                    )
                }

                grant_condition = grant_condition
                    .or(accumulator
                        .handle(syn2::parse2(tokens.clone()).map_err(darling::Error::from)));
            } else if path.is_ident("revoke") {
                if general_condition.is_some() {
                    accumulator.push(
                        darling::Error::custom(
                            "`validate_revoke` attribute can't be used with `validate` attribute",
                        )
                        .with_span(&attr),
                    )
                }
                if revoke_condition.is_some() {
                    accumulator.push(
                        darling::Error::custom(
                            "`validate_revoke` attribute duplication is not allowed",
                        )
                        .with_span(&attr),
                    )
                }

                revoke_condition = revoke_condition
                    .or(accumulator
                        .handle(syn2::parse2(tokens.clone()).map_err(darling::Error::from)));
            } else {
                unreachable!()
            }
        }

        let result = match (general_condition, grant_condition, revoke_condition) {
            (Some(condition), None, None) => Ok(ValidateAttribute::General(condition)),
            (None, Some(grant_condition), Some(revoke_condition)) => {
                Ok(ValidateAttribute::Separate {
                    grant_condition,
                    revoke_condition,
                })
            }
            (None, Some(_grant_condition), None) => {
                Err(darling::Error::custom(
                    "`validate_grant` attribute should be used together with `validate_revoke` attribute"
                ))
            }
            (None, None, Some(_revoke_condition)) => {
                Err(darling::Error::custom(
                    "`validate_revoke` attribute should be used together with `validate_grant` attribute"
                ))
            }
            (None, None, None) => Err(darling::Error::custom(
                "`validate` attribute or combination of `validate_grant` and `validate_revoke` attributes is required",
            )),
            _ => Err(darling::Error::custom("Invalid combination of attributes")),
        };

        let res = accumulator.handle(result);

        accumulator.finish().map(|()| res.unwrap())
    }
}

fn gen_validate_impls(
    attributes: &[Attribute],
) -> Result<(proc_macro2::TokenStream, proc_macro2::TokenStream)> {
    let validate_attribute = ValidateAttribute::from_attributes(attributes)?;
    match validate_attribute {
        ValidateAttribute::General(pass_condition) => Ok((
            gen_validate_impl(IsiName::Grant, &pass_condition),
            gen_validate_impl(IsiName::Revoke, &pass_condition),
        )),
        ValidateAttribute::Separate {
            grant_condition,
            revoke_condition,
        } => Ok((
            gen_validate_impl(IsiName::Grant, &grant_condition),
            gen_validate_impl(IsiName::Revoke, &revoke_condition),
        )),
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
            "Validate [`Grant`](::iroha_executor::data_model::prelude::Grant) instruction.\n"
        }
        IsiName::Revoke => {
            "Validate [`Revoke`](::iroha_executor::data_model::prelude::Revoke) instruction.\n"
        }
    };

    let pass_condition_str = pass_condition.to_token_stream().to_string();

    quote! {
        #[doc = #doc_intro]
        #[doc = "\nWrapper around [`"]
        #[doc = #pass_condition_str]
        #[doc = "`]"]
        #[inline]
        fn #fn_name(&self, authority: &::iroha_executor::data_model::account::AccountId, block_height: u64) -> ::iroha_executor::data_model::executor::Result {
            let condition = <#pass_condition as ::core::convert::From<&Self>>::from(&self);
            <
                #pass_condition
                as
                ::iroha_executor::permission::PassCondition
            >::validate(&condition, authority, block_height)
        }
    }
}
