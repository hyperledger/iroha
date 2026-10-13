//! Canonical text form for owner-qualified native settlement identities.

use super::SettlementId;
use iroha_model_base::{error::ParseError, name::Name};

impl std::str::FromStr for SettlementId {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (reference, owner) = value.split_once('$').ok_or_else(|| {
            ParseError::new("settlement id must use `reference$canonical_account`")
        })?;
        if reference.is_empty() || owner.is_empty() || owner.contains('$') {
            return Err(ParseError::new(
                "settlement id must use `reference$canonical_account`",
            ));
        }
        let reference = reference.parse::<Name>()?;
        let owner = crate::account::AccountId::parse_encoded(owner)
            .map_err(|_| ParseError::new("settlement id owner must be a canonical account"))?;
        let id = Self::new(owner, reference);
        if id.to_string() != value {
            return Err(ParseError::new(
                "settlement id must use its exact canonical spelling",
            ));
        }
        Ok(id)
    }
}
