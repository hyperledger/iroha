use iroha_data_model::prelude::*;
use iroha_structs::HashMap;

use crate::config::Configuration;

/// Returns the a map of a form `domain_name -> domain`, for initial domains.
pub fn domains(configuration: &Configuration) -> HashMap<String, Domain> {
    let key = configuration
        .genesis_configuration
        .genesis_account_public_key
        .clone();
    std::iter::once((
        GENESIS_DOMAIN_NAME.to_owned(),
        Domain::from(GenesisDomain::new(key)),
    ))
    .collect()
}
