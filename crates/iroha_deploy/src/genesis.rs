//! Shared genesis policy, default generation, and authentic core staging.
pub mod amx;
mod defaults;
pub mod profile;
pub mod staging;
pub use defaults::{ConsensusPolicy, generate_default, validate_consensus_mode};
use iroha_data_model::prelude::RoleId;
use iroha_model_base::topology::DataSpaceId;
pub use profile::PUBLIC_XOR_ALIAS;
pub use staging::bind_and_sign_staged_sumeragi_context;
/// Deterministic role used to authorize restricted-dataspace reads at the
/// universal Torii ingress hop for a private localnet profile.
pub fn private_dataspace_reader_role_id(alias: &str, dataspace: DataSpaceId) -> RoleId {
    format!(
        "private_{alias}_dataspace_{}_restricted_reader",
        dataspace.as_u64()
    )
    .parse()
    .expect("private localnet aliases must produce a valid role id")
}

#[cfg(test)]
mod tests;
