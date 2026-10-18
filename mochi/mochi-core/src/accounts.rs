//! In-memory test accounts and canonical asset literals for desktop quick actions.
//!
//! Generated keys never leave process memory: the desktop shows them only after an explicit
//! reveal, and every ledger change still goes through the reviewed transaction preview.

use crate::compose::{ComposeError, InstructionDraft, parse_account_id, parse_asset_definition_id};
use iroha_crypto::{ExposedPrivateKey, KeyPair};
use iroha_data_model::{
    account::{AccountId, address::ChainDiscriminantGuard},
    asset::id::AssetId,
};
use std::fmt;

/// A freshly generated single-signature account whose private key exists only in memory.
///
/// `Debug` is redacted so that embedding this value in diagnostics cannot disclose the key.
#[derive(Clone)]
pub struct GeneratedAccount {
    key_pair: KeyPair,
    account: AccountId,
}

impl GeneratedAccount {
    /// Generate a key pair with the default algorithm and derive its canonical account.
    #[must_use]
    pub fn generate() -> Self {
        let key_pair = KeyPair::random();
        let account = AccountId::new(key_pair.public_key().clone());
        Self { key_pair, account }
    }

    /// Canonical account identifier controlled by the generated key.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }

    /// Account literal formatted with the network's address discriminant.
    #[must_use]
    pub fn account_literal(&self, discriminant: u16) -> String {
        let _guard = ChainDiscriminantGuard::enter(discriminant);
        self.account.to_string()
    }

    /// Public key multihash for SDK and CLI configuration.
    #[must_use]
    pub fn public_key(&self) -> String {
        self.key_pair.public_key().to_string()
    }

    /// Private key multihash for local test tooling. Never log or persist this value.
    #[must_use]
    pub fn exposed_private_key(&self) -> String {
        ExposedPrivateKey(self.key_pair.private_key().clone()).to_string()
    }

    /// Draft registering this account; submission still requires a reviewed preview.
    #[must_use]
    pub fn register_draft(&self) -> InstructionDraft {
        InstructionDraft::RegisterAccount {
            account: self.account.clone(),
        }
    }
}

impl fmt::Debug for GeneratedAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedAccount")
            .field("account", &self.account)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// Canonical global-scope literal of the `definition` asset held by `account`.
///
/// Dataspace-scoped holdings keep their exact literal from state queries instead.
///
/// # Errors
/// Either identifier is not a canonical literal for the network's address discriminant.
pub fn asset_literal(
    definition: &str,
    account: &str,
    discriminant: u16,
) -> Result<String, ComposeError> {
    let _guard = ChainDiscriminantGuard::enter(discriminant);
    let definition = parse_asset_definition_id(definition.trim())?;
    let account = parse_account_id(account.trim())?;
    Ok(AssetId::new(definition, account).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCRIMINANT: u16 = 0x02F1;
    /// Canonical Base58 asset definition used by the shared composer fixtures.
    const DEFINITION: &str = "6pEP9RjNoZ7beWkT3pLfKoM1dyfi";

    #[test]
    fn generated_accounts_are_unique_registrable_and_redacted() {
        let first = GeneratedAccount::generate();
        let second = GeneratedAccount::generate();
        assert_ne!(first.account_id(), second.account_id());
        let literal = first.account_literal(DISCRIMINANT);
        let _guard = ChainDiscriminantGuard::enter(DISCRIMINANT);
        assert_eq!(
            AccountId::parse_encoded(&literal).unwrap(),
            *first.account_id()
        );
        assert!(matches!(
            first.register_draft(),
            InstructionDraft::RegisterAccount { account } if account == *first.account_id()
        ));
        let private = first.exposed_private_key();
        assert!(!private.is_empty());
        assert_ne!(private, second.exposed_private_key());
        assert!(!first.public_key().is_empty());
        let debug = format!("{first:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&private));
    }

    #[test]
    fn asset_literal_round_trips_through_the_composer() {
        let holder = GeneratedAccount::generate();
        let account = holder.account_literal(DISCRIMINANT);
        let definition = DEFINITION;
        let literal = asset_literal(&format!(" {definition} "), &account, DISCRIMINANT).unwrap();
        assert_eq!(literal, format!("{definition}#{account}"));
        let _guard = ChainDiscriminantGuard::enter(DISCRIMINANT);
        let draft = InstructionDraft::mint_from_input(&literal, "5").unwrap();
        assert!(matches!(
            draft,
            InstructionDraft::MintAsset { asset, .. }
                if asset.account() == holder.account_id() && asset.to_string() == literal
        ));
        assert!(asset_literal("not a definition", &account, DISCRIMINANT).is_err());
        assert!(asset_literal(definition, "not an account", DISCRIMINANT).is_err());
    }
}
