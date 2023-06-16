//! Definition of Iroha default validator and accompanying validation functions
#![allow(missing_docs, clippy::missing_errors_doc)]

use alloc::{borrow::ToOwned as _, vec::Vec};

use account::{
    visit_burn_account_public_key, visit_mint_account_public_key,
    visit_mint_account_signature_check_condition, visit_remove_account_key_value,
    visit_set_account_key_value, visit_unregister_account,
};
use asset::{
    visit_burn_asset, visit_mint_asset, visit_register_asset, visit_remove_asset_key_value,
    visit_set_asset_key_value, visit_transfer_asset, visit_unregister_asset,
};
use asset_definition::{
    visit_remove_asset_definition_key_value, visit_set_asset_definition_key_value,
    visit_transfer_asset_definition, visit_unregister_asset_definition,
};
use data_model::evaluate::ExpressionEvaluator;
use domain::{visit_remove_domain_key_value, visit_set_domain_key_value, visit_unregister_domain};
use iroha_wasm::data_model::visit::Visit;
use parameter::{visit_new_parameter, visit_set_parameter};
use peer::visit_unregister_peer;
use permission_token::{
    visit_grant_account_permission, visit_register_permission_token,
    visit_revoke_account_permission,
};
use role::{visit_grant_account_role, visit_revoke_account_role, visit_unregister_role};
use trigger::{visit_execute_trigger, visit_mint_trigger_repetitions, visit_unregister_trigger};
use validator::visit_upgrade_validator;

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

macro_rules! custom_impls {
    ( $($validator:ident $(<$param:ident $(: $bound:path)?>)?($operation:ty)),+ $(,)? ) => { $(
        fn $validator $(<$param $(: $bound)?>)?(&mut self, authority: &AccountId, operation: $operation) {
            $validator(self, authority, operation)
        } )+
    }
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

macro_rules! tokens {
    (
        pattern = {
            $(#[$meta:meta])*
            $vis:vis struct _ {
                $(
                    $(#[$field_meta:meta])*
                    $field_vis:vis $field:ident: $field_type:ty
                ),* $(,)?
            }
        },
        $module:ident :: tokens: [$($name:ident),+ $(,)?]
    ) => {
        declare_tokens!($(
            crate::default::$module::tokens::$name
        ),+);

        pub mod tokens {
            use super::*;

            macro_rules! single_token {
                ($name_internal:ident) => {
                    $(#[$meta])*
                    $vis struct $name_internal {
                        $(
                            $(#[$field_meta])*
                            $field_vis $field: $field_type
                        ),*
                    }
                };
            }

            $(single_token!($name);)+
        }
    };
}

pub(crate) use map_all_crate_tokens;
pub(crate) use tokens;

pub fn permission_tokens() -> Vec<PermissionTokenDefinition> {
    let mut v = Vec::new();

    macro_rules! add_to_vec {
        ($token_ty:ty) => {
            v.push(<$token_ty as ::iroha_validator::permission::Token>::definition());
        };
    }

    map_all_crate_tokens!(add_to_vec);

    v
}

impl Validate for DefaultValidator {
    fn verdict(&self) -> &Result {
        &self.verdict
    }
    fn deny(&mut self, reason: ValidationFail) {
        self.verdict = Err(reason);
    }
}

/// Validator that replaces some of [`Validate`]'s methods with sensible defaults
///
/// # Warning
///
/// The defaults are not guaranteed to be stable.
#[derive(Debug, Clone)]
pub struct DefaultValidator {
    pub verdict: Result,
    host: iroha_wasm::Host,
}

impl DefaultValidator {
    /// Construct [`Self`]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            verdict: Ok(()),
            host: iroha_wasm::Host,
        }
    }
}

impl ExpressionEvaluator for DefaultValidator {
    fn evaluate<E: Evaluate>(
        &self,
        expression: &E,
    ) -> core::result::Result<E::Value, iroha_wasm::data_model::evaluate::EvaluationError> {
        self.host.evaluate(expression)
    }
}

impl Visit for DefaultValidator {
    custom_impls! {
        visit_unsupported<T: core::fmt::Debug>(T),

        visit_transaction(&VersionedSignedTransaction),
        visit_instruction(&InstructionBox),
        visit_expression<V>(&EvaluatesTo<V>),
        visit_sequence(&SequenceBox),
        visit_if(&Conditional),
        visit_pair(&Pair),

        // Peer validation
        visit_unregister_peer(Unregister<Peer>),

        // Domain validation
        visit_unregister_domain(Unregister<Domain>),
        visit_set_domain_key_value(SetKeyValue<Domain>),
        visit_remove_domain_key_value(RemoveKeyValue<Domain>),

        // Account validation
        visit_unregister_account(Unregister<Account>),
        visit_mint_account_public_key(Mint<Account, PublicKey>),
        visit_burn_account_public_key(Burn<Account, PublicKey>),
        visit_mint_account_signature_check_condition(Mint<Account, SignatureCheckCondition>),
        visit_set_account_key_value(SetKeyValue<Account>),
        visit_remove_account_key_value(RemoveKeyValue<Account>),

        // Asset validation
        visit_register_asset(Register<Asset>),
        visit_unregister_asset(Unregister<Asset>),
        visit_mint_asset(Mint<Asset, NumericValue>),
        visit_burn_asset(Burn<Asset, NumericValue>),
        visit_transfer_asset(Transfer<Asset, NumericValue, Account>),
        visit_set_asset_key_value(SetKeyValue<Asset>),
        visit_remove_asset_key_value(RemoveKeyValue<Asset>),

        // AssetDefinition validation
        visit_unregister_asset_definition(Unregister<AssetDefinition>),
        visit_transfer_asset_definition(Transfer<Account, AssetDefinition, Account>),
        visit_set_asset_definition_key_value(SetKeyValue<AssetDefinition>),
        visit_remove_asset_definition_key_value(RemoveKeyValue<AssetDefinition>),

        // Permission validation
        visit_register_permission_token(Register<PermissionTokenDefinition>),
        visit_grant_account_permission(Grant<Account, PermissionToken>),
        visit_revoke_account_permission(Revoke<Account, PermissionToken>),

        // Role validation
        visit_unregister_role(Unregister<Role>),
        visit_grant_account_role(Grant<Account, RoleId>),
        visit_revoke_account_role(Revoke<Account, RoleId>),

        // Trigger validation
        visit_unregister_trigger(Unregister<Trigger<FilterBox, Executable>>),
        visit_mint_trigger_repetitions(Mint<Trigger<FilterBox, Executable>, u32>),
        visit_execute_trigger(ExecuteTrigger),

        // Parameter validation
        visit_set_parameter(SetParameter),
        visit_new_parameter(NewParameter),

        // Upgrade validation
        visit_upgrade_validator(Upgrade<crate::data_model::validator::Validator>),
    }
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
                        let res = isi.execute();
                        isi_validators!(@handle_isi_result res);
                    }
                }
                InstructionBox::SetParameter(isi) => {
                    let parameter = evaluate_expr!(validator, authority, <isi as NewParameter>::parameter());
                    validator.visit_set_parameter(authority, SetParameter{parameter});

                    if validator.verdict().is_ok() {
                        let res = isi.execute();
                        isi_validators!(@handle_isi_result res);
                    }
                }
                InstructionBox::ExecuteTrigger(isi) => {
                    let trigger_id = evaluate_expr!(validator, authority, <isi as ExecuteTrigger>::trigger_id());
                    validator.visit_execute_trigger(authority, ExecuteTrigger{trigger_id});

                    if validator.verdict().is_ok() {
                        let res = isi.execute();
                        isi_validators!(@handle_isi_result res);
                    }
                } $(
                InstructionBox::$isi(isi) => {
                    validator.$validator(authority, isi);

                    if validator.verdict().is_ok() {
                        let res = isi.execute();
                        isi_validators!(@handle_isi_result res);
                    }
                } )+ $(
                // NOTE: `visit_and_execute_instructions` is reentrant, so don't execute composite instructions
                InstructionBox::$composite_isi(isi) => validator.$composite_validator(authority, isi), )+
            }
        };
        (@handle_isi_result $res:ident) => {
            if let Err(err) = $res {
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

fn visit_unsupported<V: Validate + ?Sized, T: core::fmt::Debug>(
    validator: &mut V,
    _authority: &AccountId,
    item: T,
) {
    deny!(validator, "{item:?}: Unsupported operation");
}

pub fn visit_expression<V: Validate + ?Sized, X>(
    validator: &mut V,
    authority: &<Account as Identifiable>::Id,
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

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            #[derive(Clone, Copy)]
            pub struct _ {}
        },
        peer::tokens: [
            CanUnregisterAnyPeer,
        ]
    );

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_unregister_peer<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: Unregister<Peer>,
    ) {
        const CAN_UNREGISTER_PEER_TOKEN: tokens::CanUnregisterAnyPeer =
            tokens::CanUnregisterAnyPeer {};

        if CAN_UNREGISTER_PEER_TOKEN.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't unregister peer");
    }
}

pub mod domain {
    use super::*;

    // TODO: We probably need a better way to allow accounts to modify domains.
    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct _ {
                pub domain_id: <Domain as Identifiable>::Id,
            }
        },
        domain::tokens: [
            CanUnregisterDomain,
            CanSetKeyValueInDomain,
            CanRemoveKeyValueInDomain,
        ]
    );

    pub fn visit_unregister_domain<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Domain>,
    ) {
        let domain_id = isi.object_id;

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

        let can_remove_key_value_in_domain_token = tokens::CanRemoveKeyValueInDomain { domain_id };
        if can_remove_key_value_in_domain_token.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't remove key value in domain metadata");
    }
}

pub mod account {
    use super::*;

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
            #[validate(permission::account::Owner)]
            pub struct _ {
                pub account_id: AccountId,
            }
        },
        account::tokens: [
            CanUnregisterAccount,
            CanMintUserPublicKeys,
            CanBurnUserPublicKeys,
            CanMintUserSignatureCheckConditions,
            CanSetKeyValueInUserAccount,
            CanRemoveKeyValueInUserAccount,
        ]
    );

    pub fn visit_unregister_account<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Account>,
    ) {
        let account_id = isi.object_id;

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

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct _ {
                pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
            }
        },
        asset_definition::tokens: [
            CanUnregisterAssetDefinition,
            CanSetKeyValueInAssetDefinition,
            CanRemoveKeyValueInAssetDefinition,
        ]
    );

    pub(super) fn is_asset_definition_owner(
        asset_definition_id: &<AssetDefinition as Identifiable>::Id,
        authority: &<Account as Identifiable>::Id,
    ) -> Result<bool> {
        IsAssetDefinitionOwner::new(asset_definition_id.clone(), authority.clone()).execute()
    }

    pub fn visit_unregister_asset_definition<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Unregister<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id;

        match is_asset_definition_owner(&asset_definition_id, authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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
        isi: Transfer<Account, AssetDefinition, Account>,
    ) {
        let source_id = isi.source_id;
        let destination_id = isi.object;

        if &source_id == authority {
            pass!(validator);
        }
        match is_asset_definition_owner(destination_id.id(), authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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

        match is_asset_definition_owner(&asset_definition_id, authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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

        match is_asset_definition_owner(&asset_definition_id, authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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

    declare_tokens!(
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
    );

    pub mod tokens {
        use super::*;

        /// Strongly-typed representation of `can_register_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanRegisterAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_unregister_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanUnregisterAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_unregister_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanUnregisterUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_burn_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanBurnAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strong-typed representation of `can_burn_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanBurnUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_mint_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanMintAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_transfer_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanTransferAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_transfer_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanTransferUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_set_key_value_in_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanSetKeyValueInUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_remove_key_value_in_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanRemoveKeyValueInUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
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

        match asset_definition::is_asset_definition_owner(asset.id().definition_id(), authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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

        if is_asset_owner(&asset_id, authority) {
            pass!(validator);
        }
        match asset_definition::is_asset_definition_owner(asset_id.definition_id(), authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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

        match asset_definition::is_asset_definition_owner(asset_id.definition_id(), authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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

        if is_asset_owner(&asset_id, authority) {
            pass!(validator);
        }
        match asset_definition::is_asset_definition_owner(asset_id.definition_id(), authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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

        if is_asset_owner(&asset_id, authority) {
            pass!(validator);
        }
        match asset_definition::is_asset_definition_owner(asset_id.definition_id(), authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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

        /// Strongly-typed representation of `can_grant_permission_to_create_parameters` permission token.
        #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanGrantPermissionToCreateParameters;

        /// Strongly-typed representation of `can_revoke_permission_to_create_parameters` permission token.
        #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanRevokePermissionToCreateParameters;

        /// Strongly-typed representation of `can_create_parameters` permission token.
        #[derive(Token, Clone, Copy)]
        pub struct CanCreateParameters;

        impl ValidateGrantRevoke for CanCreateParameters {
            fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Result {
                if !CanGrantPermissionToCreateParameters.is_owned_by(authority) {
                    return Err(ValidationFail::NotPermitted(
                        "Can't grant permission to create new configuration parameters without permission from genesis"
                            .to_owned()
                    ));
                }

                Ok(())
            }

            fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Result {
                if !CanRevokePermissionToCreateParameters.is_owned_by(authority) {
                    return Err(ValidationFail::NotPermitted(
                        "Can't revoke permission to create new configuration parameters without permission from genesis"
                            .to_owned()
                    ));
                }

                Ok(())
            }
        }

        /// Strongly-typed representation of `can_grant_permission_to_set_parameters` permission token.
        #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanGrantPermissionToSetParameters;

        /// Strongly-typed representation of `can_revoke_permission_to_set_parameters` permission token.
        #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanRevokePermissionToSetParameters;

        /// Strongly-typed representation of `can_set_parameters` permission token.
        #[derive(Token, Clone, Copy)]
        pub struct CanSetParameters;

        impl ValidateGrantRevoke for CanSetParameters {
            fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Result {
                if !CanGrantPermissionToSetParameters.is_owned_by(authority) {
                    return Err(ValidationFail::NotPermitted(
                        "Can't grant permission to set configuration parameters without permission from genesis"
                            .to_owned()
                    ));
                }

                Ok(())
            }

            fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Result {
                if !CanRevokePermissionToSetParameters.is_owned_by(authority) {
                    return Err(ValidationFail::NotPermitted(
                        "Can't revoke permission to set configuration parameters without permission from genesis"
                            .to_owned()
                    ));
                }

                Ok(())
            }
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_new_parameter<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: NewParameter,
    ) {
        if tokens::CanCreateParameters.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(
            validator,
            "Can't create new configuration parameters without permission"
        );
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_set_parameter<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: SetParameter,
    ) {
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

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            #[derive(Clone, Copy)]
            pub struct _ {}
        },
        role::tokens: [
            CanUnregisterAnyRole,
        ]
    );

    macro_rules! impl_validate {
        ($validator:ident, $self:ident, $authority:ident, $method:ident) => {
            let role_id = $self.object;

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
                            <$token_ty as ::core::convert::TryFrom<_>>::try_from(
                                <
                                    $crate::data_model::permission::PermissionToken as
                                    ::core::clone::Clone
                                >::clone(token)
                            )
                        {
                            if let Err(error) = <$token_ty as permission::ValidateGrantRevoke>::$method(
                                &concrete_token,
                                $authority,
                            ) {
                                deny!($validator, error);
                            }

                            // Continue because token can correspond to only one concrete token
                            continue;
                        }
                    };
                }

                map_all_crate_tokens!(visit_internal);

                // In normal situation we either did early return or continue before reaching this line
                iroha_wasm::debug::dbg_panic("Role contains unknown permission token, this should never happen");
            }
        };
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_unregister_role<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: Unregister<Role>,
    ) {
        const CAN_UNREGISTER_ROLE_TOKEN: tokens::CanUnregisterAnyRole =
            tokens::CanUnregisterAnyRole {};

        if CAN_UNREGISTER_ROLE_TOKEN.is_owned_by(authority) {
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

    tokens!(
        pattern = {
            #[derive(Token, Clone, ValidateGrantRevoke)]
            #[validate(permission::trigger::Owner)]
            pub struct _ {
                pub trigger_id: <Trigger<FilterBox, Executable> as Identifiable>::Id,
            }
        },
        trigger::tokens: [
            CanExecuteUserTrigger,
            CanUnregisterUserTrigger,
            CanMintUserTrigger,
        ]
    );

    impl_froms!(
        tokens::CanExecuteUserTrigger,
        tokens::CanUnregisterUserTrigger,
        tokens::CanMintUserTrigger,
    );

    pub fn visit_unregister_trigger<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Trigger<FilterBox, Executable>>,
    ) {
        let trigger_id = isi.object_id;

        match is_trigger_owner(trigger_id.clone(), authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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
        isi: Mint<Trigger<FilterBox, Executable>, u32>,
    ) {
        let trigger_id = isi.destination_id;

        match is_trigger_owner(trigger_id.clone(), authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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

    pub fn visit_execute_trigger<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        isi: ExecuteTrigger,
    ) {
        let trigger_id = isi.trigger_id;

        match is_trigger_owner(trigger_id.clone(), authority) {
            Ok(true) => pass!(validator),
            Ok(false) => {}
            Err(err) => deny!(validator, err),
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
                    if let Ok(concrete_token) =
                        <$token_ty as ::core::convert::TryFrom<_>>::try_from(token.clone())
                    {
                        if let Err(error) = <$token_ty as permission::ValidateGrantRevoke>::$method(
                            &concrete_token,
                            $authority,
                        ) {
                            deny!($validator, error);
                        }

                        pass!($validator);
                    }
                };
            }

            map_all_crate_tokens!(visit_internal);
            deny!($validator, "Unknown permission token");
        };
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_register_permission_token<V: Validate + ?Sized>(
        validator: &mut V,
        _authority: &AccountId,
        _isi: Register<PermissionTokenDefinition>,
    ) {
        deny!(
            validator,
            "Registering new permission token is allowed only in genesis"
        );
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

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            #[derive(Clone, Copy)]
            pub struct _ {}
        },
        validator::tokens: [
            CanUpgradeValidator,
        ]
    );

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_upgrade_validator<V: Validate + ?Sized>(
        validator: &mut V,
        authority: &AccountId,
        _isi: Upgrade<data_model::validator::Validator>,
    ) {
        const CAN_UPGRADE_VALIDATOR_TOKEN: tokens::CanUpgradeValidator =
            tokens::CanUpgradeValidator {};
        if CAN_UPGRADE_VALIDATOR_TOKEN.is_owned_by(authority) {
            pass!(validator);
        }

        deny!(validator, "Can't upgrade validator");
    }
}
