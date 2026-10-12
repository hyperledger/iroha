//! Committed network identity and ledger time for SCCP admission.

use crate::state::StateReadOnly;
use iroha_data_model::NetworkId;

/// The committed context needed to bind a proof submission to this chain and its time.
pub trait SccpCommittedContext {
    /// Genesis-derived network identity.
    fn taira_network_id(&self) -> NetworkId;
    /// Canonical time of the latest committed block.
    fn committed_time_ms(&self) -> u64;
}

impl<T: StateReadOnly + ?Sized> SccpCommittedContext for T {
    fn taira_network_id(&self) -> NetworkId {
        *self.network_id()
    }

    fn committed_time_ms(&self) -> u64 {
        self.query_ledger_time_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::blank_state;

    #[test]
    fn committed_context_uses_the_state_network_and_ledger_time() {
        let state = blank_state();
        let view = state.view();
        assert_eq!(view.taira_network_id(), *view.network_id());
        assert_eq!(view.committed_time_ms(), view.query_ledger_time_ms());
    }
}
