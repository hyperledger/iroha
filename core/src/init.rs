use std::collections::BTreeMap;

use eyre::{eyre, Result};
use iroha_data_model::prelude::*;

use crate::config::Configuration;

/// Returns the a map of a form `domain_name -> domain`, for initial domains.
pub fn domains(configuration: &Configuration) -> Result<BTreeMap<DomainId, Domain>> {
    let key = configuration
        .genesis
        .account_public_key
        .clone()
        .ok_or_else(|| eyre!("Genesis account public key is not specified."))?;
    Ok(std::iter::once((
        DomainId::test(GENESIS_DOMAIN_NAME),
        Domain::from(GenesisDomain::new(key)),
    ))
    .collect())
}
