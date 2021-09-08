use std::collections::BTreeMap;

use iroha_data_model::prelude::*;
use iroha_error::{error, Result};

use crate::config::Configuration;

/// Returns the a map of a form `domain_name -> domain`, for initial domains.
pub fn domains(configuration: &Configuration) -> Result<BTreeMap<String, Domain>> {
    let key = configuration
        .genesis_configuration
        .genesis_account_public_key
        .clone()
        .ok_or_else(|| error!("Genesis account public key is not specified."))?;
    Ok(std::iter::once((
        GENESIS_DOMAIN_NAME.to_owned(),
        Domain::from(GenesisDomain::new(key)),
    ))
    .collect())
}
