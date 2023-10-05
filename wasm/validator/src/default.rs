//! Definition of Iroha default validator and accompanying validation functions
#![allow(missing_docs, clippy::missing_errors_doc)]

use alloc::{borrow::ToOwned as _, format, string::String};

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
    visit_remove_domain_key_value, visit_set_domain_key_value, visit_unregister_domain,
};
pub use parameter::{visit_new_parameter, visit_set_parameter};
pub use peer::visit_unregister_peer;
pub use permission_token::{visit_grant_account_permission, visit_revoke_account_permission};
pub use role::{
    visit_grant_account_role, visit_register_role, visit_revoke_account_role, visit_unregister_role,
};
pub use trigger::{
    visit_burn_trigger_repetitions, visit_execute_trigger, visit_mint_trigger_repetitions,
    visit_unregister_trigger,
};
pub use validator::visit_upgrade_validator;

use super::*;
use crate::{permission, permission::Token as _, prelude::*};

macro_rules! evaluate_expr {
    ($visitor:ident, $authority:ident, <$isi:ident as $isi_type:ty>::$field:ident()) => {{
        $visitor.visit_expression($authority, $isi.$field());

        $visitor.evaluate($isi.$field()).expect(&alloc::format!(
            "Failed to evaluate field '{}::{}'",
            stringify!($isi_type),
            stringify!($field),
        ))
    }};
}

/// Apply `callback` macro for all token types from this crate.
///
/// Callback technique is used because of macro expansion order. With that technique we can
/// apply callback to token types declared in other modules.
///
/// # WARNING !!!
///
/// If you add new module with tokens don't forget to add it here!
macro_rules! map_all_crate_tokens {
    ($callback:ident) => {
        $crate::default::account::map_tokens!($callback);
        $crate::default::asset::map_tokens!($callback);
        $crate::default::asset_definition::map_tokens!($callback);
        $crate::default::domain::map_tokens!($callback);
        $crate::default::parameter::map_tokens!($callback);
        $crate::default::peer::map_tokens!($callback);
        $crate::default::role::map_tokens!($callback);
        $crate::default::trigger::map_tokens!($callback);
        $crate::default::validator::map_tokens!($callback);
    };
}

macro_rules! token {
    ($($meta:meta)* $item:item) => {
        #[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[derive(iroha_schema::IntoSchema)]
        #[derive(Clone, Token)]
        $($meta)*
        $item
    };
}

pub(crate) use map_all_crate_tokens;

pub fn default_permission_token_schema() -> PermissionTokenSchema {
    let mut schema = iroha_validator::PermissionTokenSchema::default();

    macro_rules! add_to_schema {
        ($token_ty:ty) => {
            schema.insert::<$token_ty>();
        };
    }

    iroha_validator::default::map_all_crate_tokens!(add_to_schema);

    schema
}

/// Default validation for [`VersionedSignedTransaction`].
///
/// # Warning
///
/// Each instruction is executed in sequence following successful validation.
/// [`Executable::Wasm`] is not executed because it is validated on the host side.
pub fn visit_transaction<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    transaction: &VersionedSignedTransaction,
) {
    match transaction.payload().instructions() {
        Executable::Wasm(wasm) => validator.visit_wasm(authority, wasm),
        Executable::Instructions(instructions) => {
            for isi in instructions {
                if validator.verdict().is_ok() {
                    validator.visit_instruction(authority, isi);
                }
            }
        }
    }
}

/// Default validation for [`InstructionBox`].
///
/// # Warning
///
/// Instruction is executed following successful validation
pub fn visit_instruction<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    isi: &InstructionBox,
) {
    macro_rules! isi_validators {
        (
            single {$(
                $validator:ident($isi:ident)
            ),+ $(,)?}
            composite {$(
                $composite_validator:ident($composite_isi:ident)
            ),+ $(,)?}
        ) => {
            match isi {
                InstructionBox::NewParameter(isi) => {
                    let parameter = evaluate_expr!(validator, authority, <isi as NewParameter>::parameter());
                    validator.visit_new_parameter(authority, NewParameter{parameter});

                    if validator.verdict().is_ok() {
                        isi_validators!(@execute isi);
                    }
                }
                InstructionBox::SetParameter(isi) => {
                    let parameter = evaluate_expr!(validator, authority, <isi as NewParameter>::parameter());
                    validator.visit_set_parameter(authority, SetParameter{parameter});

                    if validator.verdict().is_ok() {
                        isi_validators!(@execute isi);
                    }
                }
                InstructionBox::ExecuteTrigger(isi) => {
                    let trigger_id = evaluate_expr!(validator, authority, <isi as ExecuteTrigger>::trigger_id());
                    validator.visit_execute_trigger(authority, ExecuteTrigger{trigger_id});

                    if validator.verdict().is_ok() {
                        isi_validators!(@execute isi);
                    }
                }
                InstructionBox::Log(isi) => {
                    let msg = evaluate_expr!(validator, authority, <isi as LogBox>::msg());
                    let level = evaluate_expr!(validator, authority, <isi as LogBox>::level());
                    validator.visit_log(authority, Log{level, msg});

                    if validator.verdict().is_ok() {
                        isi_validators!(@execute isi);
                    }
                } $(
                InstructionBox::$isi(isi) => {
                    validator.$validator(authority, isi);

                    if validator.verdict().is_ok() {
                        isi_validators!(@execute isi);
                    }
                } )+ $(
                // NOTE: `visit_and_execute_instructions` is reentrant, so don't execute composite instructions
                InstructionBox::$composite_isi(isi) => validator.$composite_validator(authority, isi), )+
            }
        };
        (@execute $isi:ident) => {
            // TODO: Execution should be infallible after successful validation
            if let Err(err) = isi.execute() {
                validator.deny(err);
            }
        }
    }

    isi_validators! {
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
    validator: &mut V,
    _authority: &AccountId,
    isi: T,
) {
    deny!(validator, "{isi:?}: Unsupported operation");
}

pub fn visit_expression<V: Validate + ?Sized, X>(
    validator: &mut V,
    authority: &AccountId,
    expression: &EvaluatesTo<X>,
) {
    macro_rules! visit_binary_expression {
        ($e:ident) => {{
            validator.visit_expression(authority, $e.left());

            if validator.verdict().is_ok() {
                validator.visit_expression(authority, $e.right());
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
        Expression::Not(expr) => validator.visit_expression(authority, expr.expression()),
        Expression::And(expr) => visit_binary_expression!(expr),
        Expression::Or(expr) => visit_binary_expression!(expr),
        Expression::If(expr) => {
            validator.visit_expression(authority, expr.condition());

            if validator.verdict().is_ok() {
                validator.visit_expression(authority, expr.then());
            }

            if validator.verdict().is_ok() {
                validator.visit_expression(authority, expr.otherwise());
            }
        }
        Expression::Contains(expr) => {
            validator.visit_expression(authority, expr.collection());

            if validator.verdict().is_ok() {
                validator.visit_expression(authority, expr.element());
            }
        }
        Expression::ContainsAll(expr) => {
            validator.visit_expression(authority, expr.collection());

            if validator.verdict().is_ok() {
                validator.visit_expression(authority, expr.elements());
            }
        }
        Expression::ContainsAny(expr) => {
            validator.visit_expression(authority, expr.collection());

            if validator.verdict().is_ok() {
                validator.visit_expression(authority, expr.elements());
            }
        }
        Expression::Where(expr) => validator.visit_expression(authority, expr.expression()),
        Expression::Query(query) => validator.visit_query(authority, query),
        Expression::ContextValue(_) | Expression::Raw(_) => (),
    }
}

pub fn visit_if<V: Validate + ?Sized>(validator: &mut V, authority: &AccountId, isi: &Conditional) {
    let condition = evaluate_expr!(validator, authority, <isi as Conditional>::condition());

    // TODO: Do we have to make sure both branches are syntactically valid?
    if condition {
        validator.visit_instruction(authority, isi.then());
    } else if let Some(otherwise) = isi.otherwise() {
        validator.visit_instruction(authority, otherwise);
    }
}

pub fn visit_pair<V: Validate + ?Sized>(validator: &mut V, authority: &AccountId, isi: &Pair) {
    validator.visit_instruction(authority, isi.left_instruction());

    if validator.verdict().is_ok() {
        validator.visit_instruction(authority, isi.right_instruction())
    }
}

pub fn visit_sequence<V: Validate + ?Sized>(
    validator: &mut V,
    authority: &AccountId,
    sequence: &SequenceBox,
) {
    for isi in sequence.instructions() {
        if validator.verdict().is_ok() {
            validator.visit_instruction(authority, isi);
        }
    }
}

pub mod peer {
    use super::*;

    declare_tokens! {
        crate::default::peer::tokens::CanUnregisterAnyPeer,
    }

    pub mod tokens {
        use super::*;

        token! {
            #[derive(Copy, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanUnregisterAnyPeer;
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_unregister_peer<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: Unregister<Peer>,
    ) {
        if is_genesis(validator) {
            pass!(validator);
        }
        if tokens::CanUnregisterAnyPeer.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't unregister peer");
    }
}

pub mod domain {
    use super::*;

    declare_tokens! {
        crate::default::domain::tokens::CanUnregisterDomain,
        crate::default::domain::tokens::CanSetKeyValueInDomain,
        crate::default::domain::tokens::CanRemoveKeyValueInDomain,
    }

    pub mod tokens {
        // TODO: We probably need a better way to allow accounts to modify domains.
        use super::*;

        token! {
            #[derive(ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanUnregisterDomain {
                pub domain_id: DomainId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanSetKeyValueInDomain {
                pub domain_id: DomainId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanRemoveKeyValueInDomain {
                pub domain_id: DomainId,
            }
        }
    }

    pub fn visit_unregister_domain<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Domain>,
    ) {
        let domain_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        let can_unregister_domain_token = tokens::CanUnregisterDomain { domain_id };
        if can_unregister_domain_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't unregister domain");
    }

    pub fn visit_set_domain_key_value<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Domain>,
    ) {
        let domain_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        let can_set_key_value_in_domain_token = tokens::CanSetKeyValueInDomain { domain_id };
        if can_set_key_value_in_domain_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't set key value in domain metadata");
    }

    pub fn visit_remove_domain_key_value<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Domain>,
    ) {
        let domain_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        let can_remove_key_value_in_domain_token = tokens::CanRemoveKeyValueInDomain { domain_id };
        if can_remove_key_value_in_domain_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't remove key value in domain metadata");
    }
}

pub mod account {
    use super::*;

    declare_tokens! {
        crate::default::account::tokens::CanUnregisterAccount,
        crate::default::account::tokens::CanMintUserPublicKeys,
        crate::default::account::tokens::CanBurnUserPublicKeys,
        crate::default::account::tokens::CanMintUserSignatureCheckConditions,
        crate::default::account::tokens::CanSetKeyValueInUserAccount,
        crate::default::account::tokens::CanRemoveKeyValueInUserAccount,
    }

    pub mod tokens {
        use super::*;

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
            #[validate(permission::account::Owner)]
            pub struct CanUnregisterAccount {
                pub account_id: AccountId,
            }
        }
        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
            #[validate(permission::account::Owner)]
            pub struct CanMintUserPublicKeys {
                pub account_id: AccountId,
            }
        }
        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
            #[validate(permission::account::Owner)]
            pub struct CanBurnUserPublicKeys {
                pub account_id: AccountId,
            }
        }
        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
            #[validate(permission::account::Owner)]
            pub struct CanMintUserSignatureCheckConditions {
                pub account_id: AccountId,
            }
        }
        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
            #[validate(permission::account::Owner)]
            pub struct CanSetKeyValueInUserAccount {
                pub account_id: AccountId,
            }
        }
        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
            #[validate(permission::account::Owner)]
            pub struct CanRemoveKeyValueInUserAccount {
                pub account_id: AccountId,
            }
        }
    }

    pub fn visit_unregister_account<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Account>,
    ) {
        let account_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if account_id == *authority {
            pass!(validator);
        }

        let can_unregister_user_account = tokens::CanUnregisterAccount { account_id };
        if can_unregister_user_account.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't unregister another account");
    }

    pub fn visit_mint_account_public_key<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Mint<Account, PublicKey>,
    ) {
        let account_id = isi.destination_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if account_id == *authority {
            pass!(validator);
        }
        let can_mint_user_public_keys = tokens::CanMintUserPublicKeys { account_id };
        if can_mint_user_public_keys.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't mint public keys of another account");
    }

    pub fn visit_burn_account_public_key<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Burn<Account, PublicKey>,
    ) {
        let account_id = isi.destination_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if account_id == *authority {
            pass!(validator);
        }
        let can_burn_user_public_keys = tokens::CanBurnUserPublicKeys { account_id };
        if can_burn_user_public_keys.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't burn public keys of another account");
    }

    pub fn visit_mint_account_signature_check_condition<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Mint<Account, SignatureCheckCondition>,
    ) {
        let account_id = isi.destination_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if account_id == *authority {
            pass!(validator);
        }
        let can_mint_user_signature_check_conditions_token =
            tokens::CanMintUserSignatureCheckConditions { account_id };
        if can_mint_user_signature_check_conditions_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't mint signature check conditions of another account"
        );
    }

    pub fn visit_set_account_key_value<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Account>,
    ) {
        let account_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if account_id == *authority {
            pass!(validator);
        }
        let can_set_key_value_in_user_account_token =
            tokens::CanSetKeyValueInUserAccount { account_id };
        if can_set_key_value_in_user_account_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't set value to the metadata of another account"
        );
    }

    pub fn visit_remove_account_key_value<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Account>,
    ) {
        let account_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if account_id == *authority {
            pass!(validator);
        }
        let can_remove_key_value_in_user_account_token =
            tokens::CanRemoveKeyValueInUserAccount { account_id };
        if can_remove_key_value_in_user_account_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't remove value from the metadata of another account"
        );
    }
}

pub mod asset_definition {
    use super::*;

    declare_tokens! {
        crate::default::asset_definition::tokens::CanUnregisterAssetDefinition,
        crate::default::asset_definition::tokens::CanSetKeyValueInAssetDefinition,
        crate::default::asset_definition::tokens::CanRemoveKeyValueInAssetDefinition,
    }

    pub mod tokens {
        use super::*;

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct CanUnregisterAssetDefinition {
                pub asset_definition_id: AssetDefinitionId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct CanSetKeyValueInAssetDefinition {
                pub asset_definition_id: AssetDefinitionId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct CanRemoveKeyValueInAssetDefinition {
                pub asset_definition_id: AssetDefinitionId,
            }
        }
    }

    pub(super) fn is_asset_definition_owner(
        asset_definition_id: &AssetDefinitionId,
        authority: &AccountId,
    ) -> Result<bool> {
        IsAssetDefinitionOwner::new(asset_definition_id.clone(), authority.clone()).execute()
    }

    pub fn visit_unregister_asset_definition<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Unregister<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        match is_asset_definition_owner(&asset_definition_id, authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_unregister_asset_definition_token = tokens::CanUnregisterAssetDefinition {
            asset_definition_id,
        };
        if can_unregister_asset_definition_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't unregister assets registered by other accounts"
        );
    }

    pub fn visit_transfer_asset_definition<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Transfer<Account, AssetDefinitionId, Account>,
    ) {
        let source_id = isi.source_id;
        let destination_id = isi.object;

        if is_genesis(validator) {
            pass!(validator);
        }
        if &source_id == authority {
            pass!(validator);
        }
        match is_asset_definition_owner(&destination_id, authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }

        deny!(
            validator,
            "Can't transfer asset definition of another account"
        );
    }

    pub fn visit_set_asset_definition_key_value<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        match is_asset_definition_owner(&asset_definition_id, authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_set_key_value_in_asset_definition_token = tokens::CanSetKeyValueInAssetDefinition {
            asset_definition_id,
        };
        if can_set_key_value_in_asset_definition_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't set value to the asset definition metadata created by another account"
        );
    }

    pub fn visit_remove_asset_definition_key_value<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        match is_asset_definition_owner(&asset_definition_id, authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_remove_key_value_in_asset_definition_token =
            tokens::CanRemoveKeyValueInAssetDefinition {
                asset_definition_id,
            };
        if can_remove_key_value_in_asset_definition_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't remove value from the asset definition metadata created by another account"
        );
    }
}

pub mod asset {
    use super::*;

    declare_tokens! {
        crate::default::asset::tokens::CanRegisterAssetsWithDefinition,
        crate::default::asset::tokens::CanUnregisterAssetsWithDefinition,
        crate::default::asset::tokens::CanUnregisterUserAsset,
        crate::default::asset::tokens::CanBurnAssetsWithDefinition,
        crate::default::asset::tokens::CanBurnUserAsset,
        crate::default::asset::tokens::CanMintAssetsWithDefinition,
        crate::default::asset::tokens::CanTransferAssetsWithDefinition,
        crate::default::asset::tokens::CanTransferUserAsset,
        crate::default::asset::tokens::CanSetKeyValueInUserAsset,
        crate::default::asset::tokens::CanRemoveKeyValueInUserAsset,
    }

    pub mod tokens {
        use super::*;

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct CanRegisterAssetsWithDefinition {
                pub asset_definition_id: AssetDefinitionId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct CanUnregisterAssetsWithDefinition {
                pub asset_definition_id: AssetDefinitionId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
            #[validate(permission::asset::Owner)]
            pub struct CanUnregisterUserAsset {
                pub asset_id: AssetId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct CanBurnAssetsWithDefinition {
                pub asset_definition_id: AssetDefinitionId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
            #[validate(permission::asset::Owner)]
            pub struct CanBurnUserAsset {
                pub asset_id: AssetId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct CanMintAssetsWithDefinition {
                pub asset_definition_id: AssetDefinitionId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct CanTransferAssetsWithDefinition {
                pub asset_definition_id: AssetDefinitionId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
            #[validate(permission::asset::Owner)]
            pub struct CanTransferUserAsset {
                pub asset_id: AssetId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
            #[validate(permission::asset::Owner)]
            pub struct CanSetKeyValueInUserAsset {
                pub asset_id: AssetId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
            #[validate(permission::asset::Owner)]
            pub struct CanRemoveKeyValueInUserAsset {
                pub asset_id: AssetId,
            }
        }
    }

    fn is_asset_owner(asset_id: &AssetId, authority: &AccountId) -> bool {
        asset_id.account_id() == authority
    }

    pub fn visit_register_asset<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Register<Asset>,
    ) {
        let asset = isi.object;

        if is_genesis(validator) {
            pass!(validator);
        }
        match asset_definition::is_asset_definition_owner(asset.id().definition_id(), authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_register_assets_with_definition_token = tokens::CanRegisterAssetsWithDefinition {
            asset_definition_id: asset.id().definition_id().clone(),
        };
        if can_register_assets_with_definition_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't register assets with definitions registered by other accounts"
        );
    }

    pub fn visit_unregister_asset<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Asset>,
    ) {
        let asset_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if is_asset_owner(&asset_id, authority) {
            pass!(validator);
        }
        match asset_definition::is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_unregister_assets_with_definition_token =
            tokens::CanUnregisterAssetsWithDefinition {
                asset_definition_id: asset_id.definition_id().clone(),
            };
        if can_unregister_assets_with_definition_token.is_owned_by(authority) {
            pass!(validator);
        }
        let can_unregister_user_asset_token = tokens::CanUnregisterUserAsset { asset_id };
        if can_unregister_user_asset_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't unregister asset from another account");
    }

    pub fn visit_mint_asset<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Mint<Asset, NumericValue>,
    ) {
        let asset_id = isi.destination_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        match asset_definition::is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_mint_assets_with_definition_token = tokens::CanMintAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_mint_assets_with_definition_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't mint assets with definitions registered by other accounts"
        );
    }

    pub fn visit_burn_asset<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Burn<Asset, NumericValue>,
    ) {
        let asset_id = isi.destination_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if is_asset_owner(&asset_id, authority) {
            pass!(validator);
        }
        match asset_definition::is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_burn_assets_with_definition_token = tokens::CanBurnAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_burn_assets_with_definition_token.is_owned_by(authority) {
            pass!(validator);
        }
        let can_burn_user_asset_token = tokens::CanBurnUserAsset { asset_id };
        if can_burn_user_asset_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't burn assets from another account");
    }

    pub fn visit_transfer_asset<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Transfer<Asset, NumericValue, Account>,
    ) {
        let asset_id = isi.source_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if is_asset_owner(&asset_id, authority) {
            pass!(validator);
        }
        match asset_definition::is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_transfer_assets_with_definition_token = tokens::CanTransferAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_transfer_assets_with_definition_token.is_owned_by(authority) {
            pass!(validator);
        }
        let can_transfer_user_asset_token = tokens::CanTransferUserAsset { asset_id };
        if can_transfer_user_asset_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't transfer assets of another account");
    }

    pub fn visit_set_asset_key_value<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Asset>,
    ) {
        let asset_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if is_asset_owner(&asset_id, authority) {
            pass!(validator);
        }

        let can_set_key_value_in_user_asset_token = tokens::CanSetKeyValueInUserAsset { asset_id };
        if can_set_key_value_in_user_asset_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't set value to the asset metadata of another account"
        );
    }

    pub fn visit_remove_asset_key_value<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Asset>,
    ) {
        let asset_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        if is_asset_owner(&asset_id, authority) {
            pass!(validator);
        }
        let can_remove_key_value_in_user_asset_token =
            tokens::CanRemoveKeyValueInUserAsset { asset_id };
        if can_remove_key_value_in_user_asset_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't remove value from the asset metadata of another account"
        );
    }
}

pub mod parameter {
    use permission::ValidateGrantRevoke;

    use super::*;

    declare_tokens!(
        crate::default::parameter::tokens::CanGrantPermissionToCreateParameters,
        crate::default::parameter::tokens::CanRevokePermissionToCreateParameters,
        crate::default::parameter::tokens::CanCreateParameters,
        crate::default::parameter::tokens::CanGrantPermissionToSetParameters,
        crate::default::parameter::tokens::CanRevokePermissionToSetParameters,
        crate::default::parameter::tokens::CanSetParameters,
    );

    pub mod tokens {
        use super::*;

        token! {
            #[derive(Copy, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanGrantPermissionToCreateParameters;
        }

        token! {
            #[derive(Copy, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanRevokePermissionToCreateParameters;
        }

        token! {
            #[derive(Copy)]
            pub struct CanCreateParameters;
        }

        impl ValidateGrantRevoke for CanCreateParameters {
            fn validate_grant(&self, authority: &AccountId, _block_height: u64) -> Result {
                if CanGrantPermissionToCreateParameters.is_owned_by(authority) {
                    return Ok(());
                }

                Err(ValidationFail::NotPermitted(
                        "Can't grant permission to create new configuration parameters outside genesis without permission from genesis"
                            .to_owned()
                    ))
            }

            fn validate_revoke(&self, authority: &AccountId, _block_height: u64) -> Result {
                if CanGrantPermissionToCreateParameters.is_owned_by(authority) {
                    return Ok(());
                }

                Err(ValidationFail::NotPermitted(
                        "Can't revoke permission to create new configuration parameters outside genesis without permission from genesis"
                            .to_owned()
                    ))
            }
        }

        token! {
            #[derive(Copy, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanGrantPermissionToSetParameters;
        }

        token! {
            #[derive(Copy, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanRevokePermissionToSetParameters;
        }

        token! {
            #[derive(Copy)]
            pub struct CanSetParameters;
        }

        impl ValidateGrantRevoke for CanSetParameters {
            fn validate_grant(&self, authority: &AccountId, _block_height: u64) -> Result {
                if CanGrantPermissionToSetParameters.is_owned_by(authority) {
                    return Ok(());
                }

                Err(ValidationFail::NotPermitted(
                        "Can't grant permission to set configuration parameters outside genesis without permission from genesis"
                            .to_owned()
                    ))
            }

            fn validate_revoke(&self, authority: &AccountId, _block_height: u64) -> Result {
                if CanRevokePermissionToSetParameters.is_owned_by(authority) {
                    return Ok(());
                }

                Err(ValidationFail::NotPermitted(
                        "Can't revoke permission to set configuration parameters outside genesis without permission from genesis"
                            .to_owned()
                    ))
            }
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_new_parameter<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: NewParameter,
    ) {
        if is_genesis(validator) {
            pass!(validator);
        }
        if tokens::CanCreateParameters.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't create new configuration parameters outside genesis without permission"
        );
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_set_parameter<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: SetParameter,
    ) {
        if is_genesis(validator) {
            pass!(validator);
        }
        if tokens::CanSetParameters.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't set configuration parameters without permission"
        );
    }
}

pub mod role {
    use super::*;

    declare_tokens! {
        crate::default::role::tokens::CanUnregisterAnyRole,
    }

    pub mod tokens {
        use super::*;

        token! {
            #[derive(Copy, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanUnregisterAnyRole;
        }
    }

    macro_rules! impl_validate {
        ($validator:ident, $isi:ident, $authority:ident, $method:ident) => {
            let role_id = $isi.object;

            let find_role_query_res = match FindRoleByRoleId::new(role_id).execute() {
                Ok(res) => res,
                Err(error) => {
                    deny!($validator, error);
                }
            };
            let role = Role::try_from(find_role_query_res)
                .dbg_expect("Failed to convert `FindRoleByRoleId` query result to `Role`");

            for token in role.permissions() {
                macro_rules! visit_internal {
                    ($token_ty:ty) => {
                        if let Ok(concrete_token) =
                            <$token_ty as TryFrom<_>>::try_from(token.clone())
                        {
                            if is_genesis($validator) {
                                continue;
                            }
                            if let Err(error) =
                                <$token_ty as permission::ValidateGrantRevoke>::$method(
                                    &concrete_token,
                                    $authority,
                                    $validator.block_height(),
                                )
                            {
                                deny!($validator, error);
                            }

                            // Continue because token can correspond to only one concrete token
                            continue;
                        }
                    };
                }

                map_all_crate_tokens!(visit_internal);
                deny!(
                    $validator,
                    "Incorrect validator implementation: Role contains unknown permission tokens"
                )
            }

            pass!($validator);
        };
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_register_role<V: Validate + ?Sized>(
        validator: &mut V,
        _authority: &AccountId,
        isi: Register<Role>,
    ) {
        let mut unknown_tokens = Vec::new();

        let role = isi.object.inner();
        for token in role.permissions() {
            iroha_wasm::debug!(&format!("Checking `{token:?}`"));
            macro_rules! try_from_token {
                ($token_ty:ty) => {
                    iroha_wasm::debug!(concat!("Trying `", stringify!($token_ty), "`"));
                    if <$token_ty as TryFrom<_>>::try_from(token.clone()).is_ok() {
                        iroha_wasm::debug!("Success!");
                        // Continue because token can correspond to only one concrete token
                        continue;
                    }
                };
            }

            map_all_crate_tokens!(try_from_token);
            unknown_tokens.push(token);
        }

        if !unknown_tokens.is_empty() {
            deny!(
                validator,
                ValidationFail::NotPermitted(format!(
                    "{unknown_tokens:?}: Unrecognised permission tokens"
                ))
            );
        }

        pass!(validator);
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_unregister_role<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: Unregister<Role>,
    ) {
        if is_genesis(validator) {
            pass!(validator);
        }
        if tokens::CanUnregisterAnyRole.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't unregister role");
    }

    pub fn visit_grant_account_role<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Grant<Account, RoleId>,
    ) {
        impl_validate!(validator, isi, authority, validate_grant);
    }

    pub fn visit_revoke_account_role<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Revoke<Account, RoleId>,
    ) {
        impl_validate!(validator, isi, authority, validate_revoke);
    }
}

pub mod trigger {
    use permission::trigger::is_trigger_owner;

    use super::*;

    macro_rules! impl_froms {
        ($($name:path),+ $(,)?) => {$(
            impl<'token> From<&'token $name> for permission::trigger::Owner<'token> {
                fn from(value: &'token $name) -> Self {
                    Self {
                        trigger_id: &value.trigger_id,
                    }
                }
            }
        )+};
    }

    declare_tokens! {
        crate::default::trigger::tokens::CanExecuteUserTrigger,
        crate::default::trigger::tokens::CanUnregisterUserTrigger,
        crate::default::trigger::tokens::CanMintUserTrigger,
        crate::default::trigger::tokens::CanBurnUserTrigger,
    }

    pub mod tokens {
        use super::*;

        token! {
            #[derive(ValidateGrantRevoke)]
            #[validate(permission::trigger::Owner)]
            pub struct CanExecuteUserTrigger {
                pub trigger_id: TriggerId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke)]
            #[validate(permission::trigger::Owner)]
            pub struct CanUnregisterUserTrigger {
                pub trigger_id: TriggerId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke)]
            #[validate(permission::trigger::Owner)]
            pub struct CanMintUserTrigger {
                pub trigger_id: TriggerId,
            }
        }

        token! {
            #[derive(ValidateGrantRevoke)]
            #[validate(permission::trigger::Owner)]
            pub struct CanBurnUserTrigger {
                pub trigger_id: TriggerId,
            }
        }
    }

    impl_froms!(
        tokens::CanExecuteUserTrigger,
        tokens::CanUnregisterUserTrigger,
        tokens::CanMintUserTrigger,
        tokens::CanBurnUserTrigger,
    );

    pub fn visit_unregister_trigger<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Trigger<TriggeringFilterBox, Executable>>,
    ) {
        let trigger_id = isi.object_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        match is_trigger_owner(trigger_id.clone(), authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_unregister_user_trigger_token = tokens::CanUnregisterUserTrigger { trigger_id };
        if can_unregister_user_trigger_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't unregister trigger owned by another account"
        );
    }

    pub fn visit_mint_trigger_repetitions<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Mint<Trigger<TriggeringFilterBox, Executable>, u32>,
    ) {
        let trigger_id = isi.destination_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        match is_trigger_owner(trigger_id.clone(), authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_mint_user_trigger_token = tokens::CanMintUserTrigger { trigger_id };
        if can_mint_user_trigger_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't mint execution count for trigger owned by another account"
        );
    }

    pub fn visit_burn_trigger_repetitions<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Burn<Trigger<TriggeringFilterBox, Executable>, u32>,
    ) {
        let trigger_id = isi.destination_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        match is_trigger_owner(trigger_id.clone(), authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_mint_user_trigger_token = tokens::CanMintUserTrigger { trigger_id };
        if can_mint_user_trigger_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't burn execution count for trigger owned by another account"
        );
    }

    pub fn visit_execute_trigger<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: ExecuteTrigger,
    ) {
        let trigger_id = isi.trigger_id;

        if is_genesis(validator) {
            pass!(validator);
        }
        match is_trigger_owner(trigger_id.clone(), authority) {
            Err(err) => deny!(validator, err),
            Ok(true) => pass!(validator),
            Ok(false) => {}
        }
        let can_execute_trigger_token = tokens::CanExecuteUserTrigger { trigger_id };
        if can_execute_trigger_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't execute trigger owned by another account");
    }
}

pub mod permission_token {
    use super::*;

    macro_rules! impl_validate {
        ($validator:ident, $authority:ident, $self:ident, $method:ident) => {
            let token = $self.object;

            macro_rules! visit_internal {
                ($token_ty:ty) => {
                    if let Ok(token) = <$token_ty as TryFrom<_>>::try_from(token.clone()) {
                        if is_genesis($validator) {
                            pass!($validator);
                        }
                        if let Err(error) = <$token_ty as permission::ValidateGrantRevoke>::$method(
                            &token,
                            $authority,
                            $validator.block_height(),
                        ) {
                            deny!($validator, error);
                        }

                        pass!($validator);
                    }
                };
            }

            map_all_crate_tokens!(visit_internal);

            deny!(
                $validator,
                ValidationFail::NotPermitted(format!("{token:?}: Unknown permission token"))
            );
        };
    }

    pub fn visit_grant_account_permission<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Grant<Account, PermissionToken>,
    ) {
        impl_validate!(validator, authority, isi, validate_grant);
    }

    pub fn visit_revoke_account_permission<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Revoke<Account, PermissionToken>,
    ) {
        impl_validate!(validator, authority, isi, validate_revoke);
    }
}

pub mod validator {
    use super::*;

    declare_tokens! {
        crate::default::validator::tokens::CanUpgradeValidator,
    }

    pub mod tokens {
        use super::*;

        token! {
            #[derive(Copy, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct CanUpgradeValidator;
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_upgrade_validator<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: Upgrade<data_model::validator::Validator>,
    ) {
        if is_genesis(validator) {
            pass!(validator);
        }
        if tokens::CanUpgradeValidator.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't upgrade validator");
    }
}

fn is_genesis<V: Validate + ?Sized>(validator: &V) -> bool {
    validator.block_height() == 0
}
