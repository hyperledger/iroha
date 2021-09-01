use std::collections::BTreeMap;

use iroha_data_model::prelude::*;

use crate::config::Configuration;

/// Returns the a map of a form `domain_name -> domain`, for initial domains.
#[allow(clippy::expect_used)]
pub fn domains(configuration: &Configuration) -> BTreeMap<String, Domain> {
    let key = configuration
        .genesis_configuration
        .genesis_account_public_key
        .clone()
        .expect("Genesis account public key is not specified.");
    std::iter::once((
        GENESIS_DOMAIN_NAME.to_owned(),
        Domain::from(GenesisDomain::new(key)),
    ))
    .collect()
}
