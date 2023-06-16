//! Runtime Validator which allows domain (un-)registration only for users who own
//! [`token::CanControlDomainLives`] permission token.
//!
//! It also doesn't have [`iroha_validator::default::domain::tokens::CanUnregisterDomain`].

#![no_std]

extern crate alloc;

use iroha_validator::{
    data_model::evaluate::{EvaluationError, ExpressionEvaluator},
    permission::Token as _,
    prelude::*,
};

#[cfg(not(test))]
extern crate panic_halt;

mod token {
    //! Module with custom token.

    use super::*;

    /// Token to identify if user can (un-)register domains.
    #[derive(Token, ValidateGrantRevoke)]
    #[validate(iroha_validator::permission::OnlyGenesis)]
    pub struct CanControlDomainsLives;
}

struct CustomValidator(DefaultValidator);

macro_rules! delegate {
    ( $($visitor:ident$(<$bound:ident>)?($operation:ty)),+ $(,)? ) => { $(
        fn $visitor $(<$bound>)?(&mut self, authority: &AccountId, operation: $operation) {
            self.0.$visitor(authority, operation);
        } )+
    }
}

impl CustomValidator {
    const CAN_CONTROL_DOMAIN_LIVES: token::CanControlDomainsLives = token::CanControlDomainsLives;
}

impl Visit for CustomValidator {
    fn visit_register_domain(&mut self, authority: &AccountId, _register_domain: Register<Domain>) {
        if Self::CAN_CONTROL_DOMAIN_LIVES.is_owned_by(authority) {
            pass!(self);
        }

        deny!(self, "Can't register new domain");
    }

    fn visit_unregister_domain(
        &mut self,
        authority: &AccountId,
        _unregister_domain: Unregister<Domain>,
    ) {
        if Self::CAN_CONTROL_DOMAIN_LIVES.is_owned_by(authority) {
            pass!(self);
        }

        deny!(self, "Can't unregister new domain");
    }

    delegate! {
        visit_expression<V>(&EvaluatesTo<V>),

        visit_sequence(&SequenceBox),
        visit_if(&Conditional),
        visit_pair(&Pair),

        visit_instruction(&InstructionBox),

        // Peer validation
        visit_unregister_peer(Unregister<Peer>),

        // Domain validation
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
        visit_upgrade_validator(Upgrade<iroha_validator::data_model::validator::Validator>),
    }
}

impl Validate for CustomValidator {
    fn verdict(&self) -> &Result {
        self.0.verdict()
    }
    fn deny(&mut self, reason: ValidationFail) {
        self.0.deny(reason);
    }
}

impl ExpressionEvaluator for CustomValidator {
    fn evaluate<E: Evaluate>(
        &self,
        expression: &E,
    ) -> core::result::Result<E::Value, EvaluationError> {
        self.0.evaluate(expression)
    }
}

/// Entrypoint to return permission token definitions defined in this validator.
#[entrypoint]
pub fn permission_tokens() -> Vec<PermissionTokenDefinition> {
    let mut tokens = iroha_validator::default::permission_tokens();

    // TODO: Not very convenient usage.
    // We need to come up with a better way.
    if let Some(pos) = tokens.iter().position(|definition| {
        definition == &iroha_validator::default::domain::tokens::CanUnregisterDomain::definition()
    }) {
        tokens.remove(pos);
    }

    tokens.push(token::CanControlDomainsLives::definition());
    tokens
}

/// Allow operation if authority is `admin@admin` and if not,
/// fallback to [`DefaultValidator::validate()`].
#[entrypoint(params = "[authority, operation]")]
pub fn validate(authority: AccountId, operation: NeedsValidationBox) -> Result {
    let mut validator = CustomValidator(DefaultValidator::new());

    match operation {
        NeedsValidationBox::Transaction(transaction) => {
            validator.visit_transaction(&authority, &transaction);
        }
        NeedsValidationBox::Instruction(instruction) => {
            validator.visit_instruction(&authority, &instruction);
        }
        NeedsValidationBox::Query(query) => {
            validator.visit_query(&authority, &query);
        }
    }

    validator.0.verdict
}
