//! Visitor that visits and validates every node in Iroha syntax tree
#![allow(missing_docs, clippy::missing_errors_doc)]

use alloc::borrow::ToOwned as _;

use iroha_wasm::data_model::{evaluate::ExpressionEvaluator, prelude::*, NumericValue};

use super::prelude::*;

macro_rules! delegate {
    ( $($validator:ident($operation:ty)),+ $(,)? ) => { $(
        fn $validator(&mut self, authority: &AccountId, operation: $operation) -> Verdict {
            $validator(self, authority, operation)
        } )+
    }
}

macro_rules! deny_unsupported_instruction {
    ($isi_type:ty) => {
        deny!(concat!("Unsupported `", stringify!($isi_type), "` instruction").to_owned())
    };
}

macro_rules! evaluate_expr {
    ($validator:ident, $authority:ident, <$isi:ident as $isi_type:ty>::$field:ident()) => {{
        $validator.validate_expression($authority, $isi.$field())?;

        $validator.evaluate($isi.$field()).map_err(|error| {
            alloc::format!(
                "Failed to evaluate field '{}::{}': {error}",
                stringify!($field),
                stringify!($isi_type)
            )
        })
    }};
}

/// Trait to validate Iroha entities. Default implementation always passes
///
/// This trait is based on the visitor pattern
pub trait Validate: ExpressionEvaluator {
    fn validate_expression<V>(
        &mut self,
        authority: &AccountId,
        expression: &EvaluatesTo<V>,
    ) -> Verdict {
        validate_expression(self, authority, expression)
    }

    delegate! {
        // Validate SignedTransaction
        validate_and_execute_transaction(SignedTransaction),

        // Validate TransactionPayload
        validate_and_execute_instruction(&InstructionBox),
        validate_wasm(&WasmSmartContract),
        validate_query(&QueryBox),

        // Validate InstructionBox
        validate_burn(&BurnBox),
        validate_execute_trigger(ExecuteTrigger),
        validate_fail(&FailBox),
        validate_grant(&GrantBox),
        validate_if(&Conditional),
        validate_mint(&MintBox),
        validate_new_parameter(NewParameter),
        validate_pair(&Pair),
        validate_register(&RegisterBox),
        validate_remove_key_value(&RemoveKeyValueBox),
        validate_revoke(&RevokeBox),
        validate_sequence(&SequenceBox),
        validate_set_key_value(&SetKeyValueBox),
        validate_set_parameter(SetParameter),
        validate_transfer(&TransferBox),
        validate_unregister(&UnregisterBox),
        validate_upgrade(&UpgradeBox),

        // Validate QueryBox
        validate_does_account_have_permission_token(&DoesAccountHavePermissionToken),
        validate_find_account_by_id(&FindAccountById),
        validate_find_account_key_value_by_id_and_key(&FindAccountKeyValueByIdAndKey),
        validate_find_accounts_by_domain_id(&FindAccountsByDomainId),
        validate_find_accounts_by_name(&FindAccountsByName),
        validate_find_accounts_with_asset(&FindAccountsWithAsset),
        validate_find_all_accounts(&FindAllAccounts),
        validate_find_all_active_trigger_ids(&FindAllActiveTriggerIds),
        validate_find_all_assets(&FindAllAssets),
        validate_find_all_assets_definitions(&FindAllAssetsDefinitions),
        validate_find_all_block_headers(&FindAllBlockHeaders),
        validate_find_all_blocks(&FindAllBlocks),
        validate_find_all_domains(&FindAllDomains),
        validate_find_all_parammeters(&FindAllParameters),
        validate_find_all_peers(&FindAllPeers),
        validate_find_all_permission_token_definitions(&FindAllPermissionTokenDefinitions),
        validate_find_all_role_ids(&FindAllRoleIds),
        validate_find_all_roles(&FindAllRoles),
        validate_find_all_transactions(&FindAllTransactions),
        validate_find_asset_by_id(&FindAssetById),
        validate_find_asset_definition_by_id(&FindAssetDefinitionById),
        validate_find_asset_definition_key_value_by_id_and_key(&FindAssetDefinitionKeyValueByIdAndKey),
        validate_find_asset_key_value_by_id_and_key(&FindAssetKeyValueByIdAndKey),
        validate_find_asset_quantity_by_id(&FindAssetQuantityById),
        validate_find_assets_by_account_id(&FindAssetsByAccountId),
        validate_find_assets_by_asset_definition_id(&FindAssetsByAssetDefinitionId),
        validate_find_assets_by_domain_id(&FindAssetsByDomainId),
        validate_find_assets_by_domain_id_and_asset_definition_id(&FindAssetsByDomainIdAndAssetDefinitionId),
        validate_find_assets_by_name(&FindAssetsByName),
        validate_find_block_header_by_hash(&FindBlockHeaderByHash),
        validate_find_domain_by_id(&FindDomainById),
        validate_find_domain_key_value_by_id_and_key(&FindDomainKeyValueByIdAndKey),
        validate_find_permission_tokens_by_account_id(&FindPermissionTokensByAccountId),
        validate_find_role_by_role_id(&FindRoleByRoleId),
        validate_find_roles_by_account_id(&FindRolesByAccountId),
        validate_find_total_asset_quantity_by_asset_definition_id(&FindTotalAssetQuantityByAssetDefinitionId),
        validate_find_transaction_by_hash(&FindTransactionByHash),
        validate_find_transactions_by_account_id(&FindTransactionsByAccountId),
        validate_find_trigger_by_id(&FindTriggerById),
        validate_find_trigger_key_value_by_id_and_key(&FindTriggerKeyValueByIdAndKey),
        validate_find_triggers_by_domain_id(&FindTriggersByDomainId),
        validate_is_asset_definition_owner(&IsAssetDefinitionOwner),

        // Validate RegisterBox
        validate_register_peer(Register<Peer>),
        validate_register_domain(Register<Domain>),
        validate_register_account(Register<Account>),
        validate_register_asset_definition(Register<AssetDefinition>),
        validate_register_asset(Register<Asset>),
        validate_register_role(Register<Role>),
        validate_register_trigger(Register<Trigger<FilterBox, Executable>>),
        validate_register_permission_token(Register<PermissionTokenDefinition>),

        // Validate UnregisterBox
        validate_unregister_peer(Unregister<Peer>),
        validate_unregister_domain(Unregister<Domain>),
        validate_unregister_account(Unregister<Account>),
        validate_unregister_asset_definition(Unregister<AssetDefinition>),
        validate_unregister_asset(Unregister<Asset>),
        // TODO: Need to allow role creator to unregister it somehow
        validate_unregister_role(Unregister<Role>),
        validate_unregister_trigger(Unregister<Trigger<FilterBox, Executable>>),

        // Validate MintBox
        validate_mint_asset(Mint<Asset, NumericValue>),
        validate_mint_account_public_key(Mint<Account, PublicKey>),
        validate_mint_account_signature_check_condition(Mint<Account, SignatureCheckCondition>),
        validate_mint_trigger_repetitions(Mint<Trigger<FilterBox, Executable>, u32>),

        // Validate BurnBox
        validate_burn_account_public_key(Burn<Account, PublicKey>),
        validate_burn_asset(Burn<Asset, NumericValue>),

        // Validate TransferBox
        validate_transfer_asset_definition(Transfer<Account, AssetDefinition, Account>),
        validate_transfer_asset(Transfer<Asset, NumericValue, Account>),

        // Validate SetKeyValueBox
        validate_set_domain_key_value(SetKeyValue<Domain>),
        validate_set_account_key_value(SetKeyValue<Account>),
        validate_set_asset_definition_key_value(SetKeyValue<AssetDefinition>),
        validate_set_asset_key_value(SetKeyValue<Asset>),

        // Validate RemoveKeyValueBox
        validate_remove_domain_key_value(RemoveKeyValue<Domain>),
        validate_remove_account_key_value(RemoveKeyValue<Account>),
        validate_remove_asset_definition_key_value(RemoveKeyValue<AssetDefinition>),
        validate_remove_asset_key_value(RemoveKeyValue<Asset>),

        // Validate GrantBox
        validate_grant_account_permission(Grant<Account, PermissionToken>),
        validate_grant_account_role(Grant<Account, RoleId>),

        // Validate RevokeBox
        validate_revoke_account_permission(Revoke<Account, PermissionToken>),
        validate_revoke_account_role(Revoke<Account, RoleId>),

        // Validate UpgradeBox
        validate_upgrade_validator(Upgrade<Validator>),
    }
}

/// Default validation for [`SignedTransaction`].
///
/// # Warning
///
/// Each instruction is executed in sequence following successful validation.
/// [`Executable::Wasm`] is not executed because it is validated on the host side.
// NOTE: It's always sent by value from host
// TODO: Find a way to destructure transaction
#[allow(clippy::needless_pass_by_value)]
pub fn validate_and_execute_transaction<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    transaction: SignedTransaction,
) -> Verdict {
    match transaction.payload().instructions() {
        Executable::Wasm(wasm) => validator.validate_wasm(authority, wasm),
        Executable::Instructions(instructions) => {
            for isi in instructions {
                validator.validate_and_execute_instruction(authority, isi)?;
            }

            pass!()
        }
    }
}

/// Default validation for [`QueryBox`].
pub fn validate_query<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    query: &QueryBox,
) -> Verdict {
    macro_rules! query_validators {
        ( $($validator:ident($query:ident)),+ $(,)? ) => {
            match query { $(
                QueryBox::$query(query) => validator.$validator(authority, &query), )+
            }
        };
    }

    query_validators! {
        validate_does_account_have_permission_token(DoesAccountHavePermissionToken),
        validate_find_account_by_id(FindAccountById),
        validate_find_account_key_value_by_id_and_key(FindAccountKeyValueByIdAndKey),
        validate_find_accounts_by_domain_id(FindAccountsByDomainId),
        validate_find_accounts_by_name(FindAccountsByName),
        validate_find_accounts_with_asset(FindAccountsWithAsset),
        validate_find_all_accounts(FindAllAccounts),
        validate_find_all_active_trigger_ids(FindAllActiveTriggerIds),
        validate_find_all_assets(FindAllAssets),
        validate_find_all_assets_definitions(FindAllAssetsDefinitions),
        validate_find_all_block_headers(FindAllBlockHeaders),
        validate_find_all_blocks(FindAllBlocks),
        validate_find_all_domains(FindAllDomains),
        validate_find_all_parammeters(FindAllParameters),
        validate_find_all_peers(FindAllPeers),
        validate_find_all_permission_token_definitions(FindAllPermissionTokenDefinitions),
        validate_find_all_role_ids(FindAllRoleIds),
        validate_find_all_roles(FindAllRoles),
        validate_find_all_transactions(FindAllTransactions),
        validate_find_asset_by_id(FindAssetById),
        validate_find_asset_definition_by_id(FindAssetDefinitionById),
        validate_find_asset_definition_key_value_by_id_and_key(FindAssetDefinitionKeyValueByIdAndKey),
        validate_find_asset_key_value_by_id_and_key(FindAssetKeyValueByIdAndKey),
        validate_find_asset_quantity_by_id(FindAssetQuantityById),
        validate_find_assets_by_account_id(FindAssetsByAccountId),
        validate_find_assets_by_asset_definition_id(FindAssetsByAssetDefinitionId),
        validate_find_assets_by_domain_id(FindAssetsByDomainId),
        validate_find_assets_by_domain_id_and_asset_definition_id(FindAssetsByDomainIdAndAssetDefinitionId),
        validate_find_assets_by_name(FindAssetsByName),
        validate_find_block_header_by_hash(FindBlockHeaderByHash),
        validate_find_domain_by_id(FindDomainById),
        validate_find_domain_key_value_by_id_and_key(FindDomainKeyValueByIdAndKey),
        validate_find_permission_tokens_by_account_id(FindPermissionTokensByAccountId),
        validate_find_role_by_role_id(FindRoleByRoleId),
        validate_find_roles_by_account_id(FindRolesByAccountId),
        validate_find_total_asset_quantity_by_asset_definition_id(FindTotalAssetQuantityByAssetDefinitionId),
        validate_find_transaction_by_hash(FindTransactionByHash),
        validate_find_transactions_by_account_id(FindTransactionsByAccountId),
        validate_find_trigger_by_id(FindTriggerById),
        validate_find_trigger_key_value_by_id_and_key(FindTriggerKeyValueByIdAndKey),
        validate_find_triggers_by_domain_id(FindTriggersByDomainId),
        validate_is_asset_definition_owner(IsAssetDefinitionOwner),
    }
}

/// WASM validation is done on the host side by repeatedly calling
/// [`Validate::validate_and_execute_instruction`]/[`Validate::validate_query`]
/// for every instruction/query found in the smart contract
pub fn validate_wasm<V: Validate + ?Sized>(
    _validator: &mut V,
    _authority: &AccountId,
    _wasm: &WasmSmartContract,
) -> Verdict {
    // TODO: Should we move wasm validation here if possible?
    pass!()
}

/// Default validation for [`InstructionBox`].
///
/// # Warning
///
/// Instruction is executed following successful validation
pub fn validate_and_execute_instruction<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &InstructionBox,
) -> Verdict {
    macro_rules! isi_validators {
        ( single { $($validator:ident($isi:ident)),+ $(,)? } composite: {$($composite_validator:ident($composite_isi:ident)),+ $(,)?} ) => {
            match isi {
                InstructionBox::NewParameter(isi) => {
                    let parameter = evaluate_expr!(validator, authority, <isi as NewParameter>::parameter())?;
                    validator.validate_new_parameter(authority, NewParameter{parameter})?;
                    isi.execute();
                    pass!();
                }
                InstructionBox::SetParameter(isi) => {
                    let parameter = evaluate_expr!(validator, authority, <isi as NewParameter>::parameter())?;
                    validator.validate_set_parameter(authority, SetParameter{parameter})?;
                    isi.execute();
                    pass!();
                }
                InstructionBox::ExecuteTrigger(isi) => {
                    let trigger_id = evaluate_expr!(validator, authority, <isi as ExecuteTrigger>::trigger_id())?;
                    validator.validate_execute_trigger(authority, ExecuteTrigger{trigger_id})?;
                    isi.execute();
                    pass!();
                } $(
                InstructionBox::$isi(isi) => {
                    validator.$validator(authority, isi)?;
                    isi.execute();
                    pass!();
                } )+ $(
                // NOTE: `validate_and_execute_instructions` is reentrant, so don't execute composite instructions
                InstructionBox::$composite_isi(isi) => validator.$composite_validator(authority, isi), )+
            }
        };
    }

    isi_validators! {
        single {
            validate_burn(Burn),
            validate_fail(Fail),
            validate_grant(Grant),
            validate_mint(Mint),
            validate_register(Register),
            validate_remove_key_value(RemoveKeyValue),
            validate_revoke(Revoke),
            validate_set_key_value(SetKeyValue),
            validate_transfer(Transfer),
            validate_unregister(Unregister),
            validate_upgrade(Upgrade),
        }

        composite: {
            validate_sequence(Sequence),
            validate_pair(Pair),
            validate_if(If),
        }
    }
}

pub fn validate_expression<V: Validate + ?Sized, X>(
    validator: &mut V,
    authority: &<Account as Identifiable>::Id,
    expression: &EvaluatesTo<X>,
) -> Verdict {
    macro_rules! validate_binary_math_expression {
        ($e:ident) => {{
            validator.validate_expression(authority, $e.left())?;
            validator.validate_expression(authority, $e.right())
        }};
    }

    macro_rules! validate_binary_bool_expression {
        ($e:ident) => {{
            validator.validate_expression(authority, $e.left())?;
            validator.validate_expression(authority, $e.right())
        }};
    }

    match expression.expression() {
        Expression::Add(expr) => validate_binary_math_expression!(expr),
        Expression::Subtract(expr) => validate_binary_math_expression!(expr),
        Expression::Multiply(expr) => validate_binary_math_expression!(expr),
        Expression::Divide(expr) => validate_binary_math_expression!(expr),
        Expression::Mod(expr) => validate_binary_math_expression!(expr),
        Expression::RaiseTo(expr) => validate_binary_math_expression!(expr),
        Expression::Greater(expr) => validate_binary_math_expression!(expr),
        Expression::Less(expr) => validate_binary_math_expression!(expr),
        Expression::Equal(expr) => validate_binary_bool_expression!(expr),
        Expression::Not(expr) => validator.validate_expression(authority, expr.expression()),
        Expression::And(expr) => validate_binary_bool_expression!(expr),
        Expression::Or(expr) => validate_binary_bool_expression!(expr),
        Expression::If(expr) => {
            validator.validate_expression(authority, expr.condition())?;
            validator.validate_expression(authority, expr.then())?;
            validator.validate_expression(authority, expr.otherwise())
        }
        Expression::Contains(expr) => {
            validator.validate_expression(authority, expr.collection())?;
            validator.validate_expression(authority, expr.element())
        }
        Expression::ContainsAll(expr) => {
            validator.validate_expression(authority, expr.collection())?;
            validator.validate_expression(authority, expr.elements())
        }
        Expression::ContainsAny(expr) => {
            validator.validate_expression(authority, expr.collection())?;
            validator.validate_expression(authority, expr.elements())
        }
        Expression::Where(expr) => validator.validate_expression(authority, expr.expression()),
        Expression::Query(query) => validator.validate_query(authority, query),
        Expression::ContextValue(_) | Expression::Raw(_) => pass!(),
    }
}

pub fn validate_register<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &RegisterBox,
) -> Verdict {
    macro_rules! match_all {
        ( $( $validator:ident($object:ident) ),+ $(,)? ) => {
            let object = evaluate_expr!(validator, authority, <isi as Register>::object())?;

            match object { $(
                RegistrableBox::$object(object) => validator.$validator(authority, Register{object: *object}), )+
            }
        };
    }

    match_all! {
        validate_register_peer(Peer),
        validate_register_domain(Domain),
        validate_register_account(Account),
        validate_register_asset_definition(AssetDefinition),
        validate_register_asset(Asset),
        validate_register_role(Role),
        validate_register_trigger(Trigger),

        validate_register_permission_token(PermissionTokenDefinition),
    }
}

pub fn validate_unregister<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &UnregisterBox,
) -> Verdict {
    macro_rules! match_all {
        ( $( $validator:ident($id:ident) ),+ $(,)? ) => {
            let object_id = evaluate_expr!(validator, authority, <isi as Unregister>::object_id())?;
            match object_id { $(
                IdBox::$id(object_id) => validator.$validator(authority, Unregister{object_id}), )+
                _ => deny_unsupported_instruction!(Unregister),
            }
        };
    }

    match_all! {
        validate_unregister_peer(PeerId),
        validate_unregister_domain(DomainId),
        validate_unregister_account(AccountId),
        validate_unregister_asset_definition(AssetDefinitionId),
        validate_unregister_asset(AssetId),
        validate_unregister_role(RoleId),
        validate_unregister_trigger(TriggerId),
    }
}

pub fn validate_mint<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &MintBox,
) -> Verdict {
    let destination_id = evaluate_expr!(validator, authority, <isi as Mint>::destination_id())?;
    let object = evaluate_expr!(validator, authority, <isi as Mint>::object())?;

    match (destination_id, object) {
        (IdBox::AssetId(destination_id), Value::Numeric(object)) => validator.validate_mint_asset(
            authority,
            Mint {
                object,
                destination_id,
            },
        ),
        (IdBox::AccountId(destination_id), Value::PublicKey(object)) => validator
            .validate_mint_account_public_key(
                authority,
                Mint {
                    object,
                    destination_id,
                },
            ),
        (IdBox::AccountId(destination_id), Value::SignatureCheckCondition(object)) => validator
            .validate_mint_account_signature_check_condition(
                authority,
                Mint {
                    object,
                    destination_id,
                },
            ),
        (IdBox::TriggerId(destination_id), Value::Numeric(NumericValue::U32(object))) => validator
            .validate_mint_trigger_repetitions(
                authority,
                Mint {
                    object,
                    destination_id,
                },
            ),
        _ => deny_unsupported_instruction!(Mint),
    }
}

pub fn validate_burn<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &BurnBox,
) -> Verdict {
    let destination_id = evaluate_expr!(validator, authority, <isi as Burn>::destination_id())?;
    let object = evaluate_expr!(validator, authority, <isi as Burn>::object())?;

    match (destination_id, object) {
        (IdBox::AssetId(destination_id), Value::Numeric(object)) => validator.validate_burn_asset(
            authority,
            Burn {
                object,
                destination_id,
            },
        ),
        (IdBox::AccountId(destination_id), Value::PublicKey(object)) => validator
            .validate_burn_account_public_key(
                authority,
                Burn {
                    object,
                    destination_id,
                },
            ),
        _ => deny_unsupported_instruction!(Burn),
    }
}

pub fn validate_transfer<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &TransferBox,
) -> Verdict {
    let object = evaluate_expr!(validator, authority, <isi as Transfer>::object())?;

    let (IdBox::AssetId(source_id), IdBox::AccountId(destination_id)) = (
            evaluate_expr!(validator, authority, <isi as Transfer>::source_id())?,
            evaluate_expr!(validator, authority, <isi as Transfer>::destination_id())?,
        ) else {
            deny_unsupported_instruction!(Transfer)
        };

    match object {
        Value::Numeric(object) => validator.validate_transfer_asset(
            authority,
            Transfer {
                source_id,
                object,
                destination_id,
            },
        ),
        _ => deny_unsupported_instruction!(Transfer),
    }
}

pub fn validate_set_key_value<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &SetKeyValueBox,
) -> Verdict {
    let object_id = evaluate_expr!(validator, authority, <isi as SetKeyValue>::object_id())?;
    let key = evaluate_expr!(validator, authority, <isi as SetKeyValue>::key())?;
    let value = evaluate_expr!(validator, authority, <isi as SetKeyValue>::value())?;

    match object_id {
        IdBox::AssetId(object_id) => validator.validate_set_asset_key_value(
            authority,
            SetKeyValue {
                object_id,
                key,
                value,
            },
        ),
        IdBox::AssetDefinitionId(object_id) => validator.validate_set_asset_definition_key_value(
            authority,
            SetKeyValue {
                object_id,
                key,
                value,
            },
        ),
        IdBox::AccountId(object_id) => validator.validate_set_account_key_value(
            authority,
            SetKeyValue {
                object_id,
                key,
                value,
            },
        ),
        IdBox::DomainId(object_id) => validator.validate_set_domain_key_value(
            authority,
            SetKeyValue {
                object_id,
                key,
                value,
            },
        ),
        _ => deny_unsupported_instruction!(SetKeyValue),
    }
}

pub fn validate_remove_key_value<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &RemoveKeyValueBox,
) -> Verdict {
    let object_id = evaluate_expr!(validator, authority, <isi as RemoveKeyValue>::object_id())?;
    let key = evaluate_expr!(validator, authority, <isi as RemoveKeyValue>::key())?;

    match object_id {
        IdBox::AssetId(object_id) => {
            validator.validate_remove_asset_key_value(authority, RemoveKeyValue { object_id, key })
        }
        IdBox::AssetDefinitionId(object_id) => validator
            .validate_remove_asset_definition_key_value(
                authority,
                RemoveKeyValue { object_id, key },
            ),
        IdBox::AccountId(object_id) => validator
            .validate_remove_account_key_value(authority, RemoveKeyValue { object_id, key }),
        IdBox::DomainId(object_id) => {
            validator.validate_remove_domain_key_value(authority, RemoveKeyValue { object_id, key })
        }
        _ => deny_unsupported_instruction!(SetKeyValue),
    }
}

pub fn validate_grant<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &GrantBox,
) -> Verdict {
    let destination_id = evaluate_expr!(validator, authority, <isi as Grant>::destination_id())?;
    let object = evaluate_expr!(validator, authority, <isi as Grant>::object())?;

    match (object, destination_id) {
        (Value::PermissionToken(object), IdBox::AccountId(destination_id)) => validator
            .validate_grant_account_permission(
                authority,
                Grant {
                    object,
                    destination_id,
                },
            ),
        (Value::Id(IdBox::RoleId(object)), IdBox::AccountId(destination_id)) => validator
            .validate_grant_account_role(
                authority,
                Grant {
                    object,
                    destination_id,
                },
            ),
        _ => deny_unsupported_instruction!(Grant),
    }
}

pub fn validate_revoke<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &RevokeBox,
) -> Verdict {
    let destination_id = evaluate_expr!(validator, authority, <isi as Revoke>::destination_id())?;
    let object = evaluate_expr!(validator, authority, <isi as Revoke>::object())?;

    match (destination_id, object) {
        (IdBox::AccountId(destination_id), Value::PermissionToken(object)) => validator
            .validate_revoke_account_permission(
                authority,
                Revoke {
                    object,
                    destination_id,
                },
            ),
        (IdBox::AccountId(destination_id), Value::Id(IdBox::RoleId(object))) => validator
            .validate_revoke_account_role(
                authority,
                Revoke {
                    object,
                    destination_id,
                },
            ),
        _ => deny_unsupported_instruction!(Revoke),
    }
}

pub fn validate_upgrade<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &UpgradeBox,
) -> Verdict {
    let object = evaluate_expr!(validator, authority, <isi as Upgrade>::object())?;

    match object {
        UpgradableBox::Validator(object) => {
            validator.validate_upgrade_validator(authority, Upgrade { object })
        }
    }
}

pub fn validate_if<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &Conditional,
) -> Verdict {
    let condition = evaluate_expr!(validator, authority, <isi as Conditional>::condition())?;

    // TODO: We have to make sure both branches are syntactically valid
    if condition {
        validator.validate_and_execute_instruction(authority, isi.then())?;
    } else if let Some(otherwise) = isi.otherwise() {
        validator.validate_and_execute_instruction(authority, otherwise)?;
    }

    pass!()
}

pub fn validate_pair<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &Pair,
) -> Verdict {
    validator.validate_and_execute_instruction(authority, isi.left_instruction())?;
    validator.validate_and_execute_instruction(authority, isi.right_instruction())
}

pub fn validate_sequence<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &SequenceBox,
) -> Verdict {
    for instruction in isi.instructions() {
        validator.validate_and_execute_instruction(authority, instruction)?;
    }

    pass!()
}

macro_rules! leaf_validators {
    ( $($validator:ident($operation:ty)),+ $(,)? ) => { $(
        pub fn $validator<V: Validate + ?Sized>(_validator: &mut V, _authority: &AccountId, _operation: $operation) -> Verdict {
            pass!()
        } )+
    };
}

leaf_validators! {
    // Instruction validators
    validate_register_account(Register<Account>),
    validate_unregister_account(Unregister<Account>),
    validate_mint_account_public_key(Mint<Account, PublicKey>),
    validate_burn_account_public_key(Burn<Account, PublicKey>),
    validate_mint_account_signature_check_condition(Mint<Account, SignatureCheckCondition>),
    validate_set_account_key_value(SetKeyValue<Account>),
    validate_remove_account_key_value(RemoveKeyValue<Account>),
    validate_register_asset(Register<Asset>),
    validate_unregister_asset(Unregister<Asset>),
    validate_mint_asset(Mint<Asset, NumericValue>),
    validate_burn_asset(Burn<Asset, NumericValue>),
    validate_transfer_asset(Transfer<Asset, NumericValue, Account>),
    validate_set_asset_key_value(SetKeyValue<Asset>),
    validate_remove_asset_key_value(RemoveKeyValue<Asset>),
    validate_register_asset_definition(Register<AssetDefinition>),
    validate_unregister_asset_definition(Unregister<AssetDefinition>),
    validate_transfer_asset_definition(Transfer<Account, AssetDefinition, Account>),
    validate_set_asset_definition_key_value(SetKeyValue<AssetDefinition>),
    validate_remove_asset_definition_key_value(RemoveKeyValue<AssetDefinition>),
    validate_register_domain(Register<Domain>),
    validate_unregister_domain(Unregister<Domain>),
    validate_set_domain_key_value(SetKeyValue<Domain>),
    validate_remove_domain_key_value(RemoveKeyValue<Domain>),
    validate_register_peer(Register<Peer>),
    validate_unregister_peer(Unregister<Peer>),
    validate_grant_account_permission(Grant<Account, PermissionToken>),
    validate_revoke_account_permission(Revoke<Account, PermissionToken>),
    validate_register_role(Register<Role>),
    validate_unregister_role(Unregister<Role>),
    validate_grant_account_role(Grant<Account, RoleId>),
    validate_revoke_account_role(Revoke<Account, RoleId>),
    validate_register_trigger(Register<Trigger<FilterBox, Executable>>),
    validate_unregister_trigger(Unregister<Trigger<FilterBox, Executable>>),
    validate_mint_trigger_repetitions(Mint<Trigger<FilterBox, Executable>, u32>),
    validate_upgrade_validator(Upgrade<Validator>),
    validate_new_parameter(NewParameter),
    validate_set_parameter(SetParameter),
    validate_execute_trigger(ExecuteTrigger),
    validate_register_permission_token(Register<PermissionTokenDefinition>),
    validate_fail(&FailBox),

    // Query validators
    validate_does_account_have_permission_token(&DoesAccountHavePermissionToken),
    validate_find_account_by_id(&FindAccountById),
    validate_find_account_key_value_by_id_and_key(&FindAccountKeyValueByIdAndKey),
    validate_find_accounts_by_domain_id(&FindAccountsByDomainId),
    validate_find_accounts_by_name(&FindAccountsByName),
    validate_find_accounts_with_asset(&FindAccountsWithAsset),
    validate_find_all_accounts(&FindAllAccounts),
    validate_find_all_active_trigger_ids(&FindAllActiveTriggerIds),
    validate_find_all_assets(&FindAllAssets),
    validate_find_all_assets_definitions(&FindAllAssetsDefinitions),
    validate_find_all_block_headers(&FindAllBlockHeaders),
    validate_find_all_blocks(&FindAllBlocks),
    validate_find_all_domains(&FindAllDomains),
    validate_find_all_parammeters(&FindAllParameters),
    validate_find_all_peers(&FindAllPeers),
    validate_find_all_permission_token_definitions(&FindAllPermissionTokenDefinitions),
    validate_find_all_role_ids(&FindAllRoleIds),
    validate_find_all_roles(&FindAllRoles),
    validate_find_all_transactions(&FindAllTransactions),
    validate_find_asset_by_id(&FindAssetById),
    validate_find_asset_definition_by_id(&FindAssetDefinitionById),
    validate_find_asset_definition_key_value_by_id_and_key(&FindAssetDefinitionKeyValueByIdAndKey),
    validate_find_asset_key_value_by_id_and_key(&FindAssetKeyValueByIdAndKey),
    validate_find_asset_quantity_by_id(&FindAssetQuantityById),
    validate_find_assets_by_account_id(&FindAssetsByAccountId),
    validate_find_assets_by_asset_definition_id(&FindAssetsByAssetDefinitionId),
    validate_find_assets_by_domain_id(&FindAssetsByDomainId),
    validate_find_assets_by_domain_id_and_asset_definition_id(&FindAssetsByDomainIdAndAssetDefinitionId),
    validate_find_assets_by_name(&FindAssetsByName),
    validate_find_block_header_by_hash(&FindBlockHeaderByHash),
    validate_find_domain_by_id(&FindDomainById),
    validate_find_domain_key_value_by_id_and_key(&FindDomainKeyValueByIdAndKey),
    validate_find_permission_tokens_by_account_id(&FindPermissionTokensByAccountId),
    validate_find_role_by_role_id(&FindRoleByRoleId),
    validate_find_roles_by_account_id(&FindRolesByAccountId),
    validate_find_total_asset_quantity_by_asset_definition_id(&FindTotalAssetQuantityByAssetDefinitionId),
    validate_find_transaction_by_hash(&FindTransactionByHash),
    validate_find_transactions_by_account_id(&FindTransactionsByAccountId),
    validate_find_trigger_by_id(&FindTriggerById),
    validate_find_trigger_key_value_by_id_and_key(&FindTriggerKeyValueByIdAndKey),
    validate_find_triggers_by_domain_id(&FindTriggersByDomainId),
    validate_is_asset_definition_owner(&IsAssetDefinitionOwner),
}
