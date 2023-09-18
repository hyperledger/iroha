use darling::{ast::NestedMeta, FromDeriveInput, FromMeta};
use iroha_macro_utils::Emitter;
use manyhow::emit;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn2::{parse_quote, Ident};

type ExecutorData = darling::ast::Data<darling::util::Ignored, syn2::Field>;

#[derive(Debug)]
struct Custom(Vec<Ident>);

impl FromMeta for Custom {
    fn from_list(items: &[NestedMeta]) -> darling::Result<Self> {
        let mut res = Vec::new();
        for item in items {
            if let NestedMeta::Meta(syn2::Meta::Path(p)) = item {
                let fn_name = p.get_ident().expect("Path should be ident");
                res.push(fn_name.clone());
            } else {
                return Err(darling::Error::custom(
                    "Invalid path list supplied to `omit` attribute",
                ));
            }
        }
        Ok(Self(res))
    }
}

#[derive(FromDeriveInput, Debug)]
#[darling(supports(struct_named), attributes(visit, entrypoints))]
struct ExecutorDeriveInput {
    ident: Ident,
    data: ExecutorData,
    custom: Option<Custom>,
}

pub fn impl_derive_entrypoints(emitter: &mut Emitter, input: &syn2::DeriveInput) -> TokenStream2 {
    let Some(input) = emitter.handle(ExecutorDeriveInput::from_derive_input(input)) else {
        return quote!();
    };
    let ExecutorDeriveInput {
        ident,
        data,
        custom,
        ..
    } = &input;
    check_required_fields(data, emitter);

    let (custom_idents, custom_args) = custom_field_idents_and_fn_args(data);

    let mut entrypoint_fns: Vec<syn2::ItemFn> = vec![
        parse_quote! {
            #[::iroha_executor::prelude::entrypoint]
            pub fn validate_instruction(
                authority: ::iroha_executor::prelude::AccountId,
                instruction: ::iroha_executor::prelude::InstructionExpr,
                block_height: u64,
                #(#custom_args),*
            ) -> ::iroha_executor::prelude::Result {
                let mut executor = #ident::new(block_height, #(#custom_idents),*);
                executor.visit_instruction(&authority, &instruction);
                ::core::mem::forget(instruction);
                executor.verdict
            }
        },
        parse_quote! {
            #[::iroha_executor::prelude::entrypoint]
            pub fn validate_transaction(
                authority: ::iroha_executor::prelude::AccountId,
                transaction: ::iroha_executor::prelude::SignedTransaction,
                block_height: u64,
                #(#custom_args),*
            ) -> ::iroha_executor::prelude::Result {
                let mut executor = #ident::new(block_height, #(#custom_idents),*);
                executor.visit_transaction(&authority, &transaction);
                ::core::mem::forget(transaction);
                executor.verdict
            }
        },
        parse_quote! {
            #[::iroha_executor::prelude::entrypoint]
            pub fn validate_query(
                authority: ::iroha_executor::prelude::AccountId,
                query: ::iroha_executor::prelude::QueryBox,
                block_height: u64,
                #(#custom_args),*
            ) -> ::iroha_executor::prelude::Result {
                let mut executor = #ident::new(block_height, #(#custom_idents),*);
                executor.visit_query(&authority, &query);
                ::core::mem::forget(query);
                executor.verdict
            }
        },
    ];
    if let Some(custom) = custom {
        entrypoint_fns.retain(|entrypoint| {
            !custom
                .0
                .iter()
                .any(|fn_name| fn_name == &entrypoint.sig.ident)
        });
    }

    quote! {
        #(#entrypoint_fns)*
    }
}

pub fn impl_derive_visit(emitter: &mut Emitter, input: &syn2::DeriveInput) -> TokenStream2 {
    let Some(input) = emitter.handle(ExecutorDeriveInput::from_derive_input(input)) else {
        return quote!();
    };
    let ExecutorDeriveInput { ident, custom, .. } = &input;
    let default_visit_sigs: Vec<syn2::Signature> = [
        "fn visit_unsupported<T: core::fmt::Debug>(operation: T)",
        "fn visit_transaction(operation: &SignedTransaction)",
        "fn visit_instruction(operation: &InstructionExpr)",
        "fn visit_expression<V>(operation: &EvaluatesTo<V>)",
        "fn visit_sequence(operation: &SequenceExpr)",
        "fn visit_if(operation: &ConditionalExpr)",
        "fn visit_pair(operation: &PairExpr)",
        "fn visit_unregister_peer(operation: Unregister<Peer>)",
        "fn visit_unregister_domain(operation: Unregister<Domain>)",
        "fn visit_transfer_domain(operation: Transfer<Account, DomainId, Account>)",
        "fn visit_set_domain_key_value(operation: SetKeyValue<Domain>)",
        "fn visit_remove_domain_key_value(operation: RemoveKeyValue<Domain>)",
        "fn visit_unregister_account(operation: Unregister<Account>)",
        "fn visit_mint_account_public_key(operation: Mint<PublicKey, Account>)",
        "fn visit_burn_account_public_key(operation: Burn<PublicKey, Account>)",
        "fn visit_mint_account_signature_check_condition(operation: Mint<SignatureCheckCondition, Account>)",
        "fn visit_set_account_key_value(operation: SetKeyValue<Account>)",
        "fn visit_remove_account_key_value(operation: RemoveKeyValue<Account>)",
        "fn visit_register_asset(operation: Register<Asset>)",
        "fn visit_unregister_asset(operation: Unregister<Asset>)",
        "fn visit_mint_asset(operation: Mint<NumericValue, Asset>)",
        "fn visit_burn_asset(operation: Burn<NumericValue, Asset>)",
        "fn visit_transfer_asset(operation: Transfer<Asset, NumericValue, Account>)",
        "fn visit_set_asset_key_value(operation: SetKeyValue<Asset>)",
        "fn visit_remove_asset_key_value(operation: RemoveKeyValue<Asset>)",
        "fn visit_unregister_asset_definition(operation: Unregister<AssetDefinition>)",
        "fn visit_transfer_asset_definition(operation: Transfer<Account, AssetDefinitionId, Account>)",
        "fn visit_set_asset_definition_key_value(operation: SetKeyValue<AssetDefinition>)",
        "fn visit_remove_asset_definition_key_value(operation: RemoveKeyValue<AssetDefinition>)",
        "fn visit_grant_account_permission(operation: Grant<PermissionToken>)",
        "fn visit_revoke_account_permission(operation: Revoke<PermissionToken>)",
        "fn visit_register_role(operation: Register<Role>)",
        "fn visit_unregister_role(operation: Unregister<Role>)",
        "fn visit_grant_account_role(operation: Grant<RoleId>)",
        "fn visit_revoke_account_role(operation: Revoke<RoleId>)",
        "fn visit_unregister_trigger(operation: Unregister<Trigger<TriggeringFilterBox>>)",
        "fn visit_mint_trigger_repetitions(operation: Mint<u32, Trigger<TriggeringFilterBox>>)",
        "fn visit_burn_trigger_repetitions(operation: Burn<u32, Trigger<TriggeringFilterBox>>)",
        "fn visit_execute_trigger(operation: ExecuteTrigger)",
        "fn visit_set_parameter(operation: SetParameter)",
        "fn visit_new_parameter(operation: NewParameter)",
        "fn visit_upgrade_executor(operation: Upgrade<iroha_executor::data_model::executor::Executor>)",
    ]
    .into_iter()
    .map(|item| {
        let mut sig: syn2::Signature =
            syn2::parse_str(item).expect("Function names and operation signatures should be valid");
        let recv_arg: syn2::Receiver = parse_quote!(&mut self);
        let auth_arg: syn2::FnArg = parse_quote!(authority: &AccountId);
        sig.inputs.insert(0, recv_arg.into());
        sig.inputs.insert(1, auth_arg);
        sig
    })
    .collect();

    let visit_items = default_visit_sigs
        .iter()
        .map(|visit_sig| {
            let curr_fn_name = &visit_sig.ident;
            let local_override_fn = quote! {
                #visit_sig {
                    #curr_fn_name(self, authority, operation)
                }
            };
            let default_override_fn = quote! {
                #visit_sig {
                    ::iroha_executor::default::#curr_fn_name(self, authority, operation)
                }
            };
            if let Some(fns_to_exclude) = custom {
                if fns_to_exclude
                    .0
                    .iter()
                    .any(|fn_name| fn_name == &visit_sig.ident)
                {
                    local_override_fn
                } else {
                    default_override_fn
                }
            } else {
                default_override_fn
            }
        })
        .collect::<Vec<_>>();

    println!("{}", quote!(#(#visit_items)*));
    quote! {
        impl ::iroha_executor::prelude::Visit for #ident {
            #(#visit_items)*
        }
    }
}

pub fn impl_derive_validate(emitter: &mut Emitter, input: &syn2::DeriveInput) -> TokenStream2 {
    let Some(input) = emitter.handle(ExecutorDeriveInput::from_derive_input(input)) else {
        return quote!();
    };
    let ExecutorDeriveInput { ident, data, .. } = &input;
    check_required_fields(data, emitter);
    quote! {
        impl ::iroha_executor::Validate for #ident {
            fn verdict(&self) -> &::iroha_executor::prelude::Result {
                &self.verdict
            }

            fn block_height(&self) -> u64 {
                self.block_height
            }

            fn deny(&mut self, reason: ::iroha_executor::prelude::ValidationFail) {
                self.verdict = Err(reason);
            }
        }
    }
}

pub fn impl_derive_expression_evaluator(
    emitter: &mut Emitter,
    input: &syn2::DeriveInput,
) -> TokenStream2 {
    let Some(input) = emitter.handle(ExecutorDeriveInput::from_derive_input(input)) else {
        return quote!();
    };
    let ExecutorDeriveInput { ident, data, .. } = &input;
    check_required_fields(data, emitter);
    quote! {
        impl ::iroha_executor::data_model::evaluate::ExpressionEvaluator for #ident {
            fn evaluate<E: ::iroha_executor::prelude::Evaluate>(
                &self,
                expression: &E,
            ) -> ::core::result::Result<E::Value, ::iroha_executor::smart_contract::data_model::evaluate::EvaluationError>
            {
                self.host.evaluate(expression)
            }
        }

    }
}

pub fn impl_derive_constructor(emitter: &mut Emitter, input: &syn2::DeriveInput) -> TokenStream2 {
    let Some(input) = emitter.handle(ExecutorDeriveInput::from_derive_input(input)) else {
        return quote!();
    };
    let ExecutorDeriveInput { ident, data, .. } = &input;

    check_required_fields(data, emitter);

    let (custom_idents, custom_args) = custom_field_idents_and_fn_args(data);

    // Returning an inherent impl is okay here as there can be multiple
    quote! {
        impl #ident {
            pub fn new(block_height: u64, #(#custom_args),*) -> Self {
                Self {
                    verdict: Ok(()),
                    block_height,
                    host: ::iroha_executor::smart_contract::Host,
                    #(#custom_idents),*
                }
            }
        }

    }
}

fn check_required_fields(ast: &ExecutorData, emitter: &mut Emitter) {
    let required_fields: syn2::FieldsNamed = parse_quote!({ verdict: ::iroha_executor::prelude::Result, block_height: u64, host: ::iroha_executor::smart_contract::Host });
    let struct_fields = ast
        .as_ref()
        .take_struct()
        .expect("BUG: ExecutorDeriveInput is allowed to contain struct data only")
        .fields;
    required_fields.named.iter().for_each(|required_field| {
        if !struct_fields.iter().any(|struct_field| {
            struct_field.ident == required_field.ident
                && check_type_equivalence(&required_field.ty, &struct_field.ty)
        }) {
            emit!(
                emitter,
                Span::call_site(),
                "The struct didn't have the required field named `{}` of type `{}`",
                required_field
                    .ident
                    .as_ref()
                    .expect("Required field should be named"),
                required_field.ty.to_token_stream()
            )
        }
    });
}

/// Check that the required fields of an `Executor` are of the correct types. As
/// the types can be completely or partially unqualified, we need to go through the type path segments to
/// determine equivalence. We can't account for any aliases though
fn check_type_equivalence(full_ty: &syn2::Type, given_ty: &syn2::Type) -> bool {
    match (full_ty, given_ty) {
        (syn2::Type::Path(full_ty_path), syn2::Type::Path(given_ty_path)) => {
            if full_ty_path.path.segments.len() == given_ty_path.path.segments.len() {
                full_ty_path == given_ty_path
            } else {
                full_ty_path
                    .path
                    .segments
                    .iter()
                    .rev()
                    .zip(given_ty_path.path.segments.iter().rev())
                    .all(|(full_seg, given_seg)| full_seg == given_seg)
            }
        }
        _ => false,
    }
}

/// Processes an `Executor` by draining it of default fields and returning the idents of the
/// custom fields and the corresponding function arguments for use in the constructor
fn custom_field_idents_and_fn_args(ast: &ExecutorData) -> (Vec<&Ident>, Vec<syn2::FnArg>) {
    let required_idents: Vec<Ident> = ["verdict", "block_height", "host"]
        .iter()
        .map(|s| Ident::new(s, Span::call_site()))
        .collect();
    let mut custom_fields = ast
        .as_ref()
        .take_struct()
        .expect("BUG: ExecutorDeriveInput is allowed to contain struct data only")
        .fields;
    custom_fields.retain(|field| {
        let curr_ident = field
            .ident
            .as_ref()
            .expect("BUG: Struct should have named fields");
        !required_idents.iter().any(|ident| ident == curr_ident)
    });
    let custom_idents = custom_fields
        .iter()
        .map(|field| {
            field
                .ident
                .as_ref()
                .expect("BUG: Struct should have named fields")
        })
        .collect::<Vec<_>>();
    let custom_args = custom_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            let ty = &field.ty;
            let field_arg: syn2::FnArg = parse_quote!(#ident: #ty);
            field_arg
        })
        .collect::<Vec<_>>();
    (custom_idents, custom_args)
}
