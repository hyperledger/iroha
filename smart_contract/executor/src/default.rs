//! Definition of Iroha default executor and accompanying validation functions
#![allow(missing_docs, clippy::missing_errors_doc)]

pub mod tokens;

use alloc::format;

pub use account::{
    visit_burn_account_public_key, visit_mint_account_public_key,
    visit_mint_account_signature_check_condition, visit_remove_account_key_value,
    visit_set_account_key_value, visit_unregister_account,
};
pub use asset::{
    visit_burn_asset, visit_mint_asset, visit_register_asset, visit_remove_asset_key_value,
    visit_set_asset_key_value, visit_transfer_asset, visit_unregister_asset,
};
pub use asset_definition::{
    visit_remove_asset_definition_key_value, visit_set_asset_definition_key_value,
    visit_transfer_asset_definition, visit_unregister_asset_definition,
};
pub use domain::{
    visit_remove_domain_key_value, visit_set_domain_key_value, visit_transfer_domain,
    visit_unregister_domain,
};
pub use executor::visit_upgrade_executor;
use iroha_smart_contract::debug::DebugExpectExt as _;
pub use parameter::{visit_new_parameter, visit_set_parameter};
pub use peer::visit_unregister_peer;
pub use permission_token::{visit_grant_account_permission, visit_revoke_account_permission};
pub use role::{
    visit_grant_account_role, visit_register_role, visit_revoke_account_role, visit_unregister_role,
};
pub use trigger::{
    visit_burn_trigger_repetitions, visit_execute_trigger, visit_mint_trigger_repetitions,
    visit_remove_trigger_key_value, visit_set_trigger_key_value, visit_unregister_trigger,
};

use crate::{permission, permission::Token as _, prelude::*};

macro_rules! evaluate_expr {
    ($visitor:ident, $authority:ident, <$isi:ident as $isi_type:ty>::$field:ident()) => {{
        $visitor.visit_expression($authority, $isi.$field());

        $visitor.evaluate($isi.$field()).dbg_expect(&alloc::format!(
            "Failed to evaluate field '{}::{}'",
            stringify!($isi_type),
            stringify!($field),
        ))
    }};
}

pub fn default_permission_token_schema() -> PermissionTokenSchema {
    let mut schema = iroha_executor::PermissionTokenSchema::default();

    macro_rules! add_to_schema {
        ($token_ty:ty) => {
            schema.insert::<$token_ty>();
        };
    }

    tokens::map_token_type!(add_to_schema);

    schema
}

/// Default validation for [`SignedTransaction`].
///
/// # Warning
///
/// Each instruction is executed in sequence following successful validation.
/// [`Executable::Wasm`] is not executed because it is validated on the host side.
pub fn visit_transaction<V: Validate + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    transaction: &SignedTransaction,
) {
    match transaction.payload().instructions() {
        Executable::Wasm(wasm) => executor.visit_wasm(authority, wasm),
        Executable::Instructions(instructions) => {
            for isi in instructions {
                if executor.verdict().is_ok() {
                    executor.visit_instruction(authority, isi);
                }
            }
        }
    }
}

/// Default validation for [`InstructionExpr`].
///
/// # Warning
///
/// Instruction is executed following successful validation
pub fn visit_instruction<V: Validate + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    isi: &InstructionExpr,
) {
    macro_rules! isi_executors {
        (
            single {$(
                $executor:ident($isi:ident)
            ),+ $(,)?}
            composite {$(
                $composite_executor:ident($composite_isi:ident)
            ),+ $(,)?}
        ) => {
            match isi {
                InstructionExpr::NewParameter(isi) => {
                    let parameter = evaluate_expr!(executor, authority, <isi as NewParameter>::parameter());
                    executor.visit_new_parameter(authority, NewParameter{parameter});

                    if executor.verdict().is_ok() {
                        isi_executors!(@execute isi);
                    }
                }
                InstructionExpr::SetParameter(isi) => {
                    let parameter = evaluate_expr!(executor, authority, <isi as NewParameter>::parameter());
                    executor.visit_set_parameter(authority, SetParameter{parameter});

                    if executor.verdict().is_ok() {
                        isi_executors!(@execute isi);
                    }
                }
                InstructionExpr::ExecuteTrigger(isi) => {
                    let trigger_id = evaluate_expr!(executor, authority, <isi as ExecuteTrigger>::trigger_id());
                    executor.visit_execute_trigger(authority, ExecuteTrigger{trigger_id});

                    if executor.verdict().is_ok() {
                        isi_executors!(@execute isi);
                    }
                }
                InstructionExpr::Log(isi) => {
                    let msg = evaluate_expr!(executor, authority, <isi as LogExpr>::msg());
                    let level = evaluate_expr!(executor, authority, <isi as LogExpr>::level());
                    executor.visit_log(authority, Log{level, msg});

                    if executor.verdict().is_ok() {
                        isi_executors!(@execute isi);
                    }
                } $(
                InstructionExpr::$isi(isi) => {
                    executor.$executor(authority, isi);

                    if executor.verdict().is_ok() {
                        isi_executors!(@execute isi);
                    }
                } )+ $(
                // NOTE: `visit_and_execute_instructions` is reentrant, so don't execute composite instructions
                InstructionExpr::$composite_isi(isi) => executor.$composite_executor(authority, isi), )+
            }
        };
        (@execute $isi:ident) => {
            // TODO: Execution should be infallible after successful validation
            if let Err(err) = isi.execute() {
                executor.deny(err);
            }
        }
    }

    isi_executors! {
        single {
            visit_burn(Burn),
            visit_fail(Fail),
            visit_grant(Grant),
            visit_mint(Mint),
            visit_register(Register),
            visit_remove_key_value(RemoveKeyValue),
            visit_revoke(Revoke),
            visit_set_key_value(SetKeyValue),
            visit_transfer(Transfer),
            visit_unregister(Unregister),
            visit_upgrade(Upgrade),
        }

        composite {
            visit_sequence(Sequence),
            visit_pair(Pair),
            visit_if(If),
        }
    }
}

pub fn visit_unsupported<V: Validate + ?Sized, T: core::fmt::Debug>(
    executor: &mut V,
    _authority: &AccountId,
    isi: T,
) {
    deny!(executor, "{isi:?}: Unsupported operation");
}

pub fn visit_expression<V: Validate + ?Sized, X>(
    executor: &mut V,
    authority: &AccountId,
    expression: &EvaluatesTo<X>,
) {
    macro_rules! visit_binary_expression {
        ($e:ident) => {{
            executor.visit_expression(authority, $e.left());

            if executor.verdict().is_ok() {
                executor.visit_expression(authority, $e.right());
            }
        }};
    }

    match expression.expression() {
        Expression::Add(expr) => visit_binary_expression!(expr),
        Expression::Subtract(expr) => visit_binary_expression!(expr),
        Expression::Multiply(expr) => visit_binary_expression!(expr),
        Expression::Divide(expr) => visit_binary_expression!(expr),
        Expression::Mod(expr) => visit_binary_expression!(expr),
        Expression::RaiseTo(expr) => visit_binary_expression!(expr),
        Expression::Greater(expr) => visit_binary_expression!(expr),
        Expression::Less(expr) => visit_binary_expression!(expr),
        Expression::Equal(expr) => visit_binary_expression!(expr),
        Expression::Not(expr) => executor.visit_expression(authority, expr.expression()),
        Expression::And(expr) => visit_binary_expression!(expr),
        Expression::Or(expr) => visit_binary_expression!(expr),
        Expression::If(expr) => {
            executor.visit_expression(authority, expr.condition());

            if executor.verdict().is_ok() {
                executor.visit_expression(authority, expr.then());
            }

            if executor.verdict().is_ok() {
                executor.visit_expression(authority, expr.otherwise());
            }
        }
        Expression::Contains(expr) => {
            executor.visit_expression(authority, expr.collection());

            if executor.verdict().is_ok() {
                executor.visit_expression(authority, expr.element());
            }
        }
        Expression::ContainsAll(expr) => {
            executor.visit_expression(authority, expr.collection());

            if executor.verdict().is_ok() {
                executor.visit_expression(authority, expr.elements());
            }
        }
        Expression::ContainsAny(expr) => {
            executor.visit_expression(authority, expr.collection());

            if executor.verdict().is_ok() {
                executor.visit_expression(authority, expr.elements());
            }
        }
        Expression::Where(expr) => executor.visit_expression(authority, expr.expression()),
        Expression::Query(query) => executor.visit_query(authority, query),
        Expression::ContextValue(_) | Expression::Raw(_) => (),
    }
}

pub fn visit_if<V: Validate + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    isi: &ConditionalExpr,
) {
    let condition = evaluate_expr!(executor, authority, <isi as ConditionalExpr>::condition());

    // TODO: Do we have to make sure both branches are syntactically valid?
    if condition {
        executor.visit_instruction(authority, isi.then());
    } else if let Some(otherwise) = isi.otherwise() {
        executor.visit_instruction(authority, otherwise);
    }
}

pub fn visit_pair<V: Validate + ?Sized>(executor: &mut V, authority: &AccountId, isi: &PairExpr) {
    executor.visit_instruction(authority, isi.left_instruction());

    if executor.verdict().is_ok() {
        executor.visit_instruction(authority, isi.right_instruction())
    }
}

pub fn visit_sequence<V: Validate + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    sequence: &SequenceExpr,
) {
    for isi in sequence.instructions() {
        if executor.verdict().is_ok() {
            executor.visit_instruction(authority, isi);
        }
    }
}

pub mod peer {
    use super::*;

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_unregister_peer<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        _isi: Unregister<Peer>,
    ) {
        if is_genesis(executor) {
            pass!(executor);
        }
        if tokens::peer::CanUnregisterAnyPeer.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't unregister peer");
    }
}

pub mod domain {
    use iroha_smart_contract::data_model::{domain::DomainId, permission::PermissionToken};
    use permission::{accounts_permission_tokens, domain::is_domain_owner};
    use tokens::AnyPermissionToken;

    use super::*;

    pub fn visit_unregister_domain<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Unregister<Domain>,
    ) {
        let domain_id = isi.object_id;

        if is_genesis(executor)
            || match is_domain_owner(&domain_id, authority) {
                Err(err) => deny!(executor, err),
                Ok(is_domain_owner) => is_domain_owner,
            }
            || {
                let can_unregister_domain_token = tokens::domain::CanUnregisterDomain {
                    domain_id: domain_id.clone(),
                };
                can_unregister_domain_token.is_owned_by(authority)
            }
        {
            for (owner_id, permission) in accounts_permission_tokens() {
                if is_token_domain_associated(&permission, &domain_id) {
                    let isi = RevokeExpr::new(permission, owner_id.clone());
                    if let Err(_err) = isi.execute() {
                        deny!(executor, "Can't revoke associated permission token");
                    }
                }
            }
            pass!(executor);
        }
        deny!(executor, "Can't unregister domain");
    }

    pub fn visit_transfer_domain<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Transfer<Account, DomainId, Account>,
    ) {
        let destination_id = isi.object;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_domain_owner(&destination_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }

        deny!(executor, "Can't transfer domain of another account");
    }

    pub fn visit_set_domain_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Domain>,
    ) {
        let domain_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_domain_owner(&domain_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_set_key_value_in_domain_token =
            tokens::domain::CanSetKeyValueInDomain { domain_id };
        if can_set_key_value_in_domain_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't set key value in domain metadata");
    }

    pub fn visit_remove_domain_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Domain>,
    ) {
        let domain_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_domain_owner(&domain_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_remove_key_value_in_domain_token =
            tokens::domain::CanRemoveKeyValueInDomain { domain_id };
        if can_remove_key_value_in_domain_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't remove key value in domain metadata");
    }

    #[allow(clippy::too_many_lines)]
    fn is_token_domain_associated(permission: &PermissionToken, domain_id: &DomainId) -> bool {
        let Ok(permission) = AnyPermissionToken::try_from(permission.clone()) else {
            return false;
        };
        match permission {
            AnyPermissionToken::CanUnregisterDomain(permission) => {
                &permission.domain_id == domain_id
            }
            AnyPermissionToken::CanSetKeyValueInDomain(permission) => {
                &permission.domain_id == domain_id
            }
            AnyPermissionToken::CanRemoveKeyValueInDomain(permission) => {
                &permission.domain_id == domain_id
            }
            AnyPermissionToken::CanUnregisterAssetDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanSetKeyValueInAssetDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanRemoveKeyValueInAssetDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanRegisterAssetsWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanUnregisterAssetsWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanBurnAssetsWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanMintAssetsWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanTransferAssetsWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanBurnUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanTransferUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanUnregisterUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanUnregisterAccount(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanMintUserPublicKeys(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanBurnUserPublicKeys(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanMintUserSignatureCheckConditions(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAccount(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAccount(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanUnregisterUserTrigger(permission) => {
                permission.trigger_id.domain_id().as_ref() == Some(domain_id)
            }
            AnyPermissionToken::CanExecuteUserTrigger(permission) => {
                permission.trigger_id.domain_id().as_ref() == Some(domain_id)
            }
            AnyPermissionToken::CanBurnUserTrigger(permission) => {
                permission.trigger_id.domain_id().as_ref() == Some(domain_id)
            }
            AnyPermissionToken::CanMintUserTrigger(permission) => {
                permission.trigger_id.domain_id().as_ref() == Some(domain_id)
            }
            AnyPermissionToken::CanUnregisterAnyPeer(_)
            | AnyPermissionToken::CanGrantPermissionToCreateParameters(_)
            | AnyPermissionToken::CanRevokePermissionToCreateParameters(_)
            | AnyPermissionToken::CanCreateParameters(_)
            | AnyPermissionToken::CanGrantPermissionToSetParameters(_)
            | AnyPermissionToken::CanRevokePermissionToSetParameters(_)
            | AnyPermissionToken::CanSetParameters(_)
            | AnyPermissionToken::CanUnregisterAnyRole(_)
            | AnyPermissionToken::CanUpgradeExecutor(_) => false,
        }
    }
}

pub mod account {
    use iroha_smart_contract::data_model::permission::PermissionToken;
    use permission::{account::is_account_owner, accounts_permission_tokens};
    use tokens::AnyPermissionToken;

    use super::*;

    pub fn visit_unregister_account<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Unregister<Account>,
    ) {
        let account_id = isi.object_id;

        if is_genesis(executor)
            || match is_account_owner(&account_id, authority) {
                Err(err) => deny!(executor, err),
                Ok(is_account_owner) => is_account_owner,
            }
            || {
                let can_unregister_user_account = tokens::account::CanUnregisterAccount {
                    account_id: account_id.clone(),
                };
                can_unregister_user_account.is_owned_by(authority)
            }
        {
            for (owner_id, permission) in accounts_permission_tokens() {
                if is_token_account_associated(&permission, &account_id) {
                    let isi = RevokeExpr::new(permission, owner_id.clone());
                    if let Err(_err) = isi.execute() {
                        deny!(executor, "Can't revoke associated permission token");
                    }
                }
            }
            pass!(executor);
        }
        deny!(executor, "Can't unregister another account");
    }

    pub fn visit_mint_account_public_key<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Mint<PublicKey, Account>,
    ) {
        let account_id = isi.destination_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_account_owner(&account_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_mint_user_public_keys = tokens::account::CanMintUserPublicKeys { account_id };
        if can_mint_user_public_keys.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't mint public keys of another account");
    }

    pub fn visit_burn_account_public_key<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Burn<PublicKey, Account>,
    ) {
        let account_id = isi.destination_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_account_owner(&account_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_burn_user_public_keys = tokens::account::CanBurnUserPublicKeys { account_id };
        if can_burn_user_public_keys.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't burn public keys of another account");
    }

    pub fn visit_mint_account_signature_check_condition<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Mint<SignatureCheckCondition, Account>,
    ) {
        let account_id = isi.destination_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_account_owner(&account_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_mint_user_signature_check_conditions_token =
            tokens::account::CanMintUserSignatureCheckConditions { account_id };
        if can_mint_user_signature_check_conditions_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't mint signature check conditions of another account"
        );
    }

    pub fn visit_set_account_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Account>,
    ) {
        let account_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_account_owner(&account_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_set_key_value_in_user_account_token =
            tokens::account::CanSetKeyValueInUserAccount { account_id };
        if can_set_key_value_in_user_account_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't set value to the metadata of another account"
        );
    }

    pub fn visit_remove_account_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Account>,
    ) {
        let account_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_account_owner(&account_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_remove_key_value_in_user_account_token =
            tokens::account::CanRemoveKeyValueInUserAccount { account_id };
        if can_remove_key_value_in_user_account_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't remove value from the metadata of another account"
        );
    }

    fn is_token_account_associated(permission: &PermissionToken, account_id: &AccountId) -> bool {
        let Ok(permission) = AnyPermissionToken::try_from(permission.clone()) else {
            return false;
        };
        match permission {
            AnyPermissionToken::CanUnregisterAccount(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanMintUserPublicKeys(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanBurnUserPublicKeys(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanMintUserSignatureCheckConditions(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAccount(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAccount(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanBurnUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanTransferUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanUnregisterUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanUnregisterUserTrigger(_)
            | AnyPermissionToken::CanExecuteUserTrigger(_)
            | AnyPermissionToken::CanBurnUserTrigger(_)
            | AnyPermissionToken::CanMintUserTrigger(_)
            | AnyPermissionToken::CanUnregisterAnyPeer(_)
            | AnyPermissionToken::CanUnregisterDomain(_)
            | AnyPermissionToken::CanSetKeyValueInDomain(_)
            | AnyPermissionToken::CanRemoveKeyValueInDomain(_)
            | AnyPermissionToken::CanUnregisterAssetDefinition(_)
            | AnyPermissionToken::CanSetKeyValueInAssetDefinition(_)
            | AnyPermissionToken::CanRemoveKeyValueInAssetDefinition(_)
            | AnyPermissionToken::CanRegisterAssetsWithDefinition(_)
            | AnyPermissionToken::CanUnregisterAssetsWithDefinition(_)
            | AnyPermissionToken::CanBurnAssetsWithDefinition(_)
            | AnyPermissionToken::CanMintAssetsWithDefinition(_)
            | AnyPermissionToken::CanTransferAssetsWithDefinition(_)
            | AnyPermissionToken::CanGrantPermissionToCreateParameters(_)
            | AnyPermissionToken::CanRevokePermissionToCreateParameters(_)
            | AnyPermissionToken::CanCreateParameters(_)
            | AnyPermissionToken::CanGrantPermissionToSetParameters(_)
            | AnyPermissionToken::CanRevokePermissionToSetParameters(_)
            | AnyPermissionToken::CanSetParameters(_)
            | AnyPermissionToken::CanUnregisterAnyRole(_)
            | AnyPermissionToken::CanUpgradeExecutor(_) => false,
        }
    }
}

pub mod asset_definition {
    use iroha_smart_contract::data_model::{asset::AssetDefinitionId, permission::PermissionToken};
    use permission::{
        account::is_account_owner, accounts_permission_tokens,
        asset_definition::is_asset_definition_owner,
    };
    use tokens::AnyPermissionToken;

    use super::*;

    pub fn visit_unregister_asset_definition<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Unregister<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id;

        if is_genesis(executor)
            || match is_asset_definition_owner(&asset_definition_id, authority) {
                Err(err) => deny!(executor, err),
                Ok(is_asset_definition_owner) => is_asset_definition_owner,
            }
            || {
                let can_unregister_asset_definition_token =
                    tokens::asset_definition::CanUnregisterAssetDefinition {
                        asset_definition_id: asset_definition_id.clone(),
                    };
                can_unregister_asset_definition_token.is_owned_by(authority)
            }
        {
            for (owner_id, permission) in accounts_permission_tokens() {
                if is_token_asset_definition_associated(&permission, &asset_definition_id) {
                    let isi = RevokeExpr::new(permission, owner_id.clone());
                    if let Err(_err) = isi.execute() {
                        deny!(executor, "Can't revoke associated permission token");
                    }
                }
            }
            pass!(executor);
        }
        deny!(
            executor,
            "Can't unregister assets registered by other accounts"
        );
    }

    pub fn visit_transfer_asset_definition<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Transfer<Account, AssetDefinitionId, Account>,
    ) {
        let source_id = isi.source_id;
        let destination_id = isi.object;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_account_owner(&source_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        match is_asset_definition_owner(&destination_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }

        deny!(
            executor,
            "Can't transfer asset definition of another account"
        );
    }

    pub fn visit_set_asset_definition_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_asset_definition_owner(&asset_definition_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_set_key_value_in_asset_definition_token =
            tokens::asset_definition::CanSetKeyValueInAssetDefinition {
                asset_definition_id,
            };
        if can_set_key_value_in_asset_definition_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't set value to the asset definition metadata created by another account"
        );
    }

    pub fn visit_remove_asset_definition_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_asset_definition_owner(&asset_definition_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_remove_key_value_in_asset_definition_token =
            tokens::asset_definition::CanRemoveKeyValueInAssetDefinition {
                asset_definition_id,
            };
        if can_remove_key_value_in_asset_definition_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't remove value from the asset definition metadata created by another account"
        );
    }

    fn is_token_asset_definition_associated(
        permission: &PermissionToken,
        asset_definition_id: &AssetDefinitionId,
    ) -> bool {
        let Ok(permission) = AnyPermissionToken::try_from(permission.clone()) else {
            return false;
        };
        match permission {
            AnyPermissionToken::CanUnregisterAssetDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanSetKeyValueInAssetDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanRemoveKeyValueInAssetDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanRegisterAssetsWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanUnregisterAssetsWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanBurnAssetsWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanMintAssetsWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanTransferAssetsWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanBurnUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanTransferUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanUnregisterUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanUnregisterAccount(_)
            | AnyPermissionToken::CanMintUserPublicKeys(_)
            | AnyPermissionToken::CanBurnUserPublicKeys(_)
            | AnyPermissionToken::CanMintUserSignatureCheckConditions(_)
            | AnyPermissionToken::CanSetKeyValueInUserAccount(_)
            | AnyPermissionToken::CanRemoveKeyValueInUserAccount(_)
            | AnyPermissionToken::CanUnregisterUserTrigger(_)
            | AnyPermissionToken::CanExecuteUserTrigger(_)
            | AnyPermissionToken::CanBurnUserTrigger(_)
            | AnyPermissionToken::CanMintUserTrigger(_)
            | AnyPermissionToken::CanUnregisterAnyPeer(_)
            | AnyPermissionToken::CanUnregisterDomain(_)
            | AnyPermissionToken::CanSetKeyValueInDomain(_)
            | AnyPermissionToken::CanRemoveKeyValueInDomain(_)
            | AnyPermissionToken::CanGrantPermissionToCreateParameters(_)
            | AnyPermissionToken::CanRevokePermissionToCreateParameters(_)
            | AnyPermissionToken::CanCreateParameters(_)
            | AnyPermissionToken::CanGrantPermissionToSetParameters(_)
            | AnyPermissionToken::CanRevokePermissionToSetParameters(_)
            | AnyPermissionToken::CanSetParameters(_)
            | AnyPermissionToken::CanUnregisterAnyRole(_)
            | AnyPermissionToken::CanUpgradeExecutor(_) => false,
        }
    }
}

pub mod asset {
    use permission::{asset::is_asset_owner, asset_definition::is_asset_definition_owner};

    use super::*;

    pub fn visit_register_asset<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Register<Asset>,
    ) {
        let asset = isi.object;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_asset_definition_owner(asset.id().definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_register_assets_with_definition_token =
            tokens::asset::CanRegisterAssetsWithDefinition {
                asset_definition_id: asset.id().definition_id().clone(),
            };
        if can_register_assets_with_definition_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't register assets with definitions registered by other accounts"
        );
    }

    pub fn visit_unregister_asset<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Unregister<Asset>,
    ) {
        let asset_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_asset_owner(&asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        match is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_unregister_assets_with_definition_token =
            tokens::asset::CanUnregisterAssetsWithDefinition {
                asset_definition_id: asset_id.definition_id().clone(),
            };
        if can_unregister_assets_with_definition_token.is_owned_by(authority) {
            pass!(executor);
        }
        let can_unregister_user_asset_token = tokens::asset::CanUnregisterUserAsset { asset_id };
        if can_unregister_user_asset_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't unregister asset from another account");
    }

    pub fn visit_mint_asset<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Mint<NumericValue, Asset>,
    ) {
        let asset_id = isi.destination_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_mint_assets_with_definition_token = tokens::asset::CanMintAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_mint_assets_with_definition_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't mint assets with definitions registered by other accounts"
        );
    }

    pub fn visit_burn_asset<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Burn<NumericValue, Asset>,
    ) {
        let asset_id = isi.destination_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_asset_owner(&asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        match is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_burn_assets_with_definition_token = tokens::asset::CanBurnAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_burn_assets_with_definition_token.is_owned_by(authority) {
            pass!(executor);
        }
        let can_burn_user_asset_token = tokens::asset::CanBurnUserAsset { asset_id };
        if can_burn_user_asset_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't burn assets from another account");
    }

    pub fn visit_transfer_asset<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Transfer<Asset, NumericValue, Account>,
    ) {
        let asset_id = isi.source_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_asset_owner(&asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        match is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_transfer_assets_with_definition_token =
            tokens::asset::CanTransferAssetsWithDefinition {
                asset_definition_id: asset_id.definition_id().clone(),
            };
        if can_transfer_assets_with_definition_token.is_owned_by(authority) {
            pass!(executor);
        }
        let can_transfer_user_asset_token = tokens::asset::CanTransferUserAsset { asset_id };
        if can_transfer_user_asset_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't transfer assets of another account");
    }

    pub fn visit_set_asset_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Asset>,
    ) {
        let asset_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_asset_owner(&asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }

        let can_set_key_value_in_user_asset_token =
            tokens::asset::CanSetKeyValueInUserAsset { asset_id };
        if can_set_key_value_in_user_asset_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't set value to the asset metadata of another account"
        );
    }

    pub fn visit_remove_asset_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Asset>,
    ) {
        let asset_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_asset_owner(&asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_remove_key_value_in_user_asset_token =
            tokens::asset::CanRemoveKeyValueInUserAsset { asset_id };
        if can_remove_key_value_in_user_asset_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't remove value from the asset metadata of another account"
        );
    }
}

pub mod parameter {
    use super::*;

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_new_parameter<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        _isi: NewParameter,
    ) {
        if is_genesis(executor) {
            pass!(executor);
        }
        if tokens::parameter::CanCreateParameters.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't create new configuration parameters outside genesis without permission"
        );
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_set_parameter<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        _isi: SetParameter,
    ) {
        if is_genesis(executor) {
            pass!(executor);
        }
        if tokens::parameter::CanSetParameters.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't set configuration parameters without permission"
        );
    }
}

pub mod role {
    use super::*;

    macro_rules! impl_validate {
        ($executor:ident, $isi:ident, $authority:ident, $method:ident) => {
            let role_id = $isi.object;

            let find_role_query_res = match FindRoleByRoleId::new(role_id).execute() {
                Ok(res) => res,
                Err(error) => {
                    deny!($executor, error);
                }
            };
            let role = Role::try_from(find_role_query_res).unwrap();

            let mut unknown_tokens = Vec::new();
            for token in role.permissions() {
                macro_rules! visit_internal {
                    ($token:ident) => {
                        if !is_genesis($executor) {
                            if let Err(error) = permission::ValidateGrantRevoke::$method(
                                    &$token,
                                    $authority,
                                    $executor.block_height(),
                                )
                            {
                                deny!($executor, error);
                            }
                        }

                        continue;
                    };
                }

                tokens::map_token!(token => visit_internal);
                unknown_tokens.push(token);
            }

            assert!(unknown_tokens.is_empty(), "Role contains unknown permission tokens: {unknown_tokens:?}");
        };
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_register_role<V: Validate + ?Sized>(
        executor: &mut V,
        _authority: &AccountId,
        isi: Register<Role>,
    ) {
        let role = isi.object.inner();

        let mut unknown_tokens = Vec::new();
        for token in role.permissions() {
            iroha_smart_contract::debug!(&format!("Checking `{token:?}`"));

            macro_rules! try_from_token {
                ($token:ident) => {
                    let _token = $token;
                    continue;
                };
            }

            tokens::map_token!(token => try_from_token);
            unknown_tokens.push(token);
        }

        if !unknown_tokens.is_empty() {
            deny!(
                executor,
                ValidationFail::NotPermitted(format!(
                    "{unknown_tokens:?}: Unrecognised permission tokens"
                ))
            );
        }

        pass!(executor);
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_unregister_role<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        _isi: Unregister<Role>,
    ) {
        if is_genesis(executor) {
            pass!(executor);
        }
        if tokens::role::CanUnregisterAnyRole.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't unregister role");
    }

    pub fn visit_grant_account_role<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Grant<RoleId>,
    ) {
        impl_validate!(executor, isi, authority, validate_grant);
    }

    pub fn visit_revoke_account_role<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Revoke<RoleId>,
    ) {
        impl_validate!(executor, isi, authority, validate_revoke);
    }
}

pub mod trigger {
    use iroha_smart_contract::data_model::{permission::PermissionToken, trigger::TriggerId};
    use permission::{accounts_permission_tokens, trigger::is_trigger_owner};
    use tokens::AnyPermissionToken;

    use super::*;

    pub fn visit_unregister_trigger<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Unregister<Trigger<TriggeringFilterBox>>,
    ) {
        let trigger_id = isi.object_id;

        if is_genesis(executor)
            || match is_trigger_owner(&trigger_id, authority) {
                Err(err) => deny!(executor, err),
                Ok(is_trigger_owner) => is_trigger_owner,
            }
            || {
                let can_unregister_user_trigger_token = tokens::trigger::CanUnregisterUserTrigger {
                    trigger_id: trigger_id.clone(),
                };
                can_unregister_user_trigger_token.is_owned_by(authority)
            }
        {
            for (owner_id, permission) in accounts_permission_tokens() {
                if is_token_trigger_associated(&permission, &trigger_id) {
                    let isi = RevokeExpr::new(permission, owner_id.clone());
                    if let Err(_err) = isi.execute() {
                        deny!(executor, "Can't revoke associated permission token");
                    }
                }
            }
            pass!(executor);
        }
        deny!(
            executor,
            "Can't unregister trigger owned by another account"
        );
    }

    pub fn visit_mint_trigger_repetitions<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Mint<u32, Trigger<TriggeringFilterBox>>,
    ) {
        let trigger_id = isi.destination_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_trigger_owner(&trigger_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_mint_user_trigger_token = tokens::trigger::CanMintUserTrigger { trigger_id };
        if can_mint_user_trigger_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't mint execution count for trigger owned by another account"
        );
    }

    pub fn visit_burn_trigger_repetitions<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Burn<u32, Trigger<TriggeringFilterBox>>,
    ) {
        let trigger_id = isi.destination_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_trigger_owner(&trigger_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_mint_user_trigger_token = tokens::trigger::CanBurnUserTrigger { trigger_id };
        if can_mint_user_trigger_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't burn execution count for trigger owned by another account"
        );
    }

    pub fn visit_execute_trigger<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: ExecuteTrigger,
    ) {
        let trigger_id = isi.trigger_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_trigger_owner(&trigger_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_execute_trigger_token = tokens::trigger::CanExecuteUserTrigger { trigger_id };
        if can_execute_trigger_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't execute trigger owned by another account");
    }

    pub fn visit_set_trigger_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Trigger<TriggeringFilterBox>>,
    ) {
        let trigger_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_trigger_owner(&trigger_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_set_key_value_in_user_trigger_token =
            tokens::trigger::CanSetKeyValueInTrigger { trigger_id };
        if can_set_key_value_in_user_trigger_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't set value to the metadata of another trigger"
        );
    }

    pub fn visit_remove_trigger_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Trigger<TriggeringFilterBox>>,
    ) {
        let trigger_id = isi.object_id;

        if is_genesis(executor) {
            pass!(executor);
        }
        match is_trigger_owner(&trigger_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => pass!(executor),
            Ok(false) => {}
        }
        let can_remove_key_value_in_trigger_token =
            tokens::trigger::CanRemoveKeyValueInTrigger { trigger_id };
        if can_remove_key_value_in_trigger_token.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(
            executor,
            "Can't remove value from the metadata of another trigger"
        );
    }

    fn is_token_trigger_associated(permission: &PermissionToken, trigger_id: &TriggerId) -> bool {
        let Ok(permission) = AnyPermissionToken::try_from(permission.clone()) else {
            return false;
        };
        match permission {
            AnyPermissionToken::CanUnregisterUserTrigger(permission) => {
                &permission.trigger_id == trigger_id
            }
            AnyPermissionToken::CanExecuteUserTrigger(permission) => {
                &permission.trigger_id == trigger_id
            }
            AnyPermissionToken::CanBurnUserTrigger(permission) => {
                &permission.trigger_id == trigger_id
            }
            AnyPermissionToken::CanMintUserTrigger(permission) => {
                &permission.trigger_id == trigger_id
            }
            AnyPermissionToken::CanUnregisterAnyPeer(_)
            | AnyPermissionToken::CanUnregisterDomain(_)
            | AnyPermissionToken::CanSetKeyValueInDomain(_)
            | AnyPermissionToken::CanRemoveKeyValueInDomain(_)
            | AnyPermissionToken::CanUnregisterAccount(_)
            | AnyPermissionToken::CanMintUserPublicKeys(_)
            | AnyPermissionToken::CanBurnUserPublicKeys(_)
            | AnyPermissionToken::CanMintUserSignatureCheckConditions(_)
            | AnyPermissionToken::CanSetKeyValueInUserAccount(_)
            | AnyPermissionToken::CanRemoveKeyValueInUserAccount(_)
            | AnyPermissionToken::CanUnregisterAssetDefinition(_)
            | AnyPermissionToken::CanSetKeyValueInAssetDefinition(_)
            | AnyPermissionToken::CanRemoveKeyValueInAssetDefinition(_)
            | AnyPermissionToken::CanRegisterAssetsWithDefinition(_)
            | AnyPermissionToken::CanUnregisterAssetsWithDefinition(_)
            | AnyPermissionToken::CanUnregisterUserAsset(_)
            | AnyPermissionToken::CanBurnAssetsWithDefinition(_)
            | AnyPermissionToken::CanBurnUserAsset(_)
            | AnyPermissionToken::CanMintAssetsWithDefinition(_)
            | AnyPermissionToken::CanTransferAssetsWithDefinition(_)
            | AnyPermissionToken::CanTransferUserAsset(_)
            | AnyPermissionToken::CanSetKeyValueInUserAsset(_)
            | AnyPermissionToken::CanRemoveKeyValueInUserAsset(_)
            | AnyPermissionToken::CanGrantPermissionToCreateParameters(_)
            | AnyPermissionToken::CanRevokePermissionToCreateParameters(_)
            | AnyPermissionToken::CanCreateParameters(_)
            | AnyPermissionToken::CanGrantPermissionToSetParameters(_)
            | AnyPermissionToken::CanRevokePermissionToSetParameters(_)
            | AnyPermissionToken::CanSetParameters(_)
            | AnyPermissionToken::CanUnregisterAnyRole(_)
            | AnyPermissionToken::CanUpgradeExecutor(_) => false,
        }
    }
}

pub mod permission_token {
    use super::*;

    macro_rules! impl_validate {
        ($executor:ident, $authority:ident, $self:ident, $method:ident) => {
            let token = $self.object;

            macro_rules! visit_internal {
                ($token:ident) => {
                    if is_genesis($executor) {
                        pass!($executor);
                    }
                    if let Err(error) = permission::ValidateGrantRevoke::$method(
                        &$token,
                        $authority,
                        $executor.block_height(),
                    ) {
                        deny!($executor, error);
                    }

                    pass!($executor);
                };
            }

            tokens::map_token!(token => visit_internal);

            deny!(
                $executor,
                ValidationFail::NotPermitted(format!("{token:?}: Unknown permission token"))
            );
        };
    }

    pub fn visit_grant_account_permission<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Grant<PermissionToken>,
    ) {
        impl_validate!(executor, authority, isi, validate_grant);
    }

    pub fn visit_revoke_account_permission<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: Revoke<PermissionToken>,
    ) {
        impl_validate!(executor, authority, isi, validate_revoke);
    }
}

pub mod executor {
    use super::*;

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_upgrade_executor<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        _isi: Upgrade<crate::data_model::executor::Executor>,
    ) {
        if is_genesis(executor) {
            pass!(executor);
        }
        if tokens::executor::CanUpgradeExecutor.is_owned_by(authority) {
            pass!(executor);
        }

        deny!(executor, "Can't upgrade executor");
    }
}

fn is_genesis<V: Validate + ?Sized>(executor: &V) -> bool {
    executor.block_height() == 0
}
