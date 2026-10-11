//! Launch metadata retained only after the signed native genesis executes successfully.

use iroha_crypto::Hash;
use iroha_data_model::NetworkId;

/// Signed network, committee size and execution policies authenticated during offline genesis
/// validation.
/// Construction is private to the daemon's original validation boundary.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedGenesis {
    pub(crate) network_id: NetworkId,
    /// Ready committee size retained from original native genesis execution.
    pub(crate) initial_committee_size: usize,
    pub(crate) execution_policy_hash: Hash,
    pub(crate) nexus_amx_context_hash: Hash,
}
