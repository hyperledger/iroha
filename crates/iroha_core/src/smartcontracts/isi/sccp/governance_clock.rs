//! SCCP rank-three work and same-pass emergency enactments under one external budget.

use super::{
    fast_pause::certification::{self, CertifiedPause},
    keepalive::DueWorkUnavailable,
    parliament_iface, reconciliation_store, store,
};
use crate::state::{StateBlock, StateBlockStartError};
use iroha_data_model::{
    block::consensus::SumeragiRootScope, bridge::SccpNetworkV1, sccp::fast_pause::SccpPanelRoleV1,
};

/// At most two certified panels for each of the three external networks.
pub(crate) struct PauseEnactments {
    items: [Option<CertifiedPause>; 6],
}
impl PauseEnactments {
    /// Resume only after every Parliament enactment, on the same original shared pass.
    pub(crate) fn enact<E: std::fmt::Debug>(
        self,
        state: &mut StateBlock<'_>,
    ) -> Result<(), StateBlockStartError<E>> {
        if self.items.iter().all(Option::is_none) {
            return Ok(());
        }
        parliament_iface::with_sccp_g3_prefix(state, |state, cursor| {
            for item in self.items.into_iter().flatten() {
                let Some(position) = cursor
                    .take_enactment_position(state)
                    .map_err(StateBlockStartError::GovernanceDueUnavailable)?
                else {
                    break;
                };
                certification::enact(state, item, position)?;
            }
            state
                .require_storage_admission()
                .map_err(StateBlockStartError::Storage)
        })
    }
}
/// G2a union key: time, network, kind (pause before reconciliation), role/revision.
/// Role values are primary zero and backup one. No incomparable heterogeneous keys.
fn pause_key(
    time: u64,
    network: SccpNetworkV1,
    role: SccpPanelRoleV1,
) -> (u64, SccpNetworkV1, u8, u64) {
    (
        time,
        network,
        0,
        match role {
            SccpPanelRoleV1::Primary => 0,
            SccpPanelRoleV1::Backup => 1,
        },
    )
}

/// Merge due closes and panel conclusions without replacing Parliament's remaining budget.
pub(crate) fn advance_reconciliation<E: std::fmt::Debug>(
    state: &mut StateBlock<'_>,
) -> Result<PauseEnactments, StateBlockStartError<E>> {
    let mut batch = PauseEnactments {
        items: std::array::from_fn(|_| None),
    };
    if state.sumeragi_schedule.original_root_scope() != Some(SumeragiRootScope::Global) {
        return Ok(batch);
    }
    let time = state._curr_block.creation_time_ms;
    let mut panels = [None; 6];
    let mut count = 0;
    for ((network, role), round) in store::fast_pause_rounds::iter(&state.world) {
        if round.certify_due {
            if count == panels.len() {
                return Err(StateBlockStartError::Policy(
                    "SCCP panel round key bound exceeded".into(),
                ));
            }
            panels[count] = Some((*network, *role));
            count += 1;
        }
    }
    if count == 0 && reconciliation_store::earliest_due(&state.world, time).is_none() {
        return Ok(batch);
    }
    parliament_iface::with_sccp_g2a_prefix(state, |state, cursor| {
        let mut panel_index = 0;
        loop {
            let reconciliation = reconciliation_store::earliest_due(&state.world, time);
            let panel = panels.get(panel_index).copied().flatten();
            let select_panel = match (panel, reconciliation) {
                (None, None) => break,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (Some((network, role)), Some((due, other, revision))) => {
                    pause_key(time, network, role) < (due, other, 1, u64::from(revision))
                }
            };
            let Some(_position) = cursor
                .take_rank_three_position(state)
                .map_err(StateBlockStartError::GovernanceDueUnavailable)?
            else {
                break;
            };
            if select_panel {
                let Some((network, role)) = panel else {
                    return Err(StateBlockStartError::GovernanceDueUnavailable(
                        DueWorkUnavailable,
                    ));
                };
                batch.items[panel_index] = certification::certify(state, network, role)?;
                panel_index += 1;
            } else {
                let Some((_, network, revision)) = reconciliation else {
                    return Err(StateBlockStartError::GovernanceDueUnavailable(
                        DueWorkUnavailable,
                    ));
                };
                let mut tx = state
                    .try_transaction()
                    .map_err(StateBlockStartError::Storage)?;
                let result = super::reconciliation::end_one(&mut tx, network, revision);
                tx.require_storage_admission()
                    .map_err(StateBlockStartError::Storage)?;
                match result {
                    Ok(true) => tx.apply(),
                    Ok(false) => {
                        return Err(StateBlockStartError::GovernanceDueUnavailable(
                            DueWorkUnavailable,
                        ));
                    }
                    Err(error) => return Err(StateBlockStartError::Policy(error.to_string())),
                }
            }
        }
        state
            .require_storage_admission()
            .map_err(StateBlockStartError::Storage)
    })?;
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sccp_rank_three_union_orders_due_time_network_kind_then_role_or_revision() {
        let network = SccpNetworkV1::EthereumMainnet;
        let primary = pause_key(100, network, SccpPanelRoleV1::Primary);
        let backup = pause_key(100, network, SccpPanelRoleV1::Backup);
        assert!(primary < backup);
        assert!(backup < (100, network, 1, 1));
        assert!((99, network, 1, 9) < primary);
        assert!(backup < pause_key(100, SccpNetworkV1::BscMainnet, SccpPanelRoleV1::Primary));
    }
}
