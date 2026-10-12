//! Expiry cleanup of original SCCP fast-pause records (§4.7.2 G4, §4.14.7).
//!
//! Expiry already stops holding without a block. This consumer removes the record and
//! reports its lapse on the next original Global block, after all enacted effects. It
//! grants no pause creation or lift authority. TODO: the actual shared positioned pass,
//! panel producers and Policy Jury casting-open source for selective lift remain open.

use super::store;
use crate::state::{StateBlock, StateStorageAdmissionError};
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    bridge::SccpNetworkV1,
    sccp::events::{SccpEvent, SccpFastPauseLapsedV1},
};

// Closed external network tags, in protocol order. No collected key or record graph.
const EXTERNAL_NETWORKS: [SccpNetworkV1; 3] = [
    SccpNetworkV1::EthereumMainnet,
    SccpNetworkV1::BscMainnet,
    SccpNetworkV1::TonMainnet,
];

/// Apply only G4 to this exact native Global overlay, after Parliament enactments.
/// No subject head, control nonce, leaf or independent Parliament flag changes.
///
/// # Errors
/// Preserves the original storage refusal. The caller must discard its refused block;
/// no record or event is published until the normal native output is certified.
#[inline(never)]
pub(crate) fn lapse_after_enactments(
    state: &mut StateBlock<'_>,
) -> Result<(), StateStorageAdmissionError> {
    if state.sumeragi_schedule.original_root_scope() != Some(SumeragiRootScope::Global)
        || store::parameters::get(&state.world).is_none()
    {
        return Ok(());
    }
    if cfg!(all(test, sumeragi_core_mutation = "HC246")) {
        return Ok(());
    }
    let time = state._curr_block.creation_time_ms;
    if !EXTERNAL_NETWORKS.iter().any(|network| {
        store::fast_pauses::get(&state.world, network)
            .is_some_and(|original| time >= original.until_ms)
    }) {
        return Ok(());
    }
    let mut transaction = state.try_transaction()?;
    for network in EXTERNAL_NETWORKS {
        let Some(event) = store::fast_pauses::get(&*transaction.world, &network)
            .filter(|original| time >= original.until_ms)
            .map(|original| SccpFastPauseLapsedV1 {
                network,
                certificate_id: original.certificate_id,
                until_ms: original.until_ms,
            })
        else {
            continue;
        };
        let _original = store::fast_pauses::remove(&mut transaction, network);
        transaction.require_storage_admission()?;
        transaction
            .world
            .emit_events(Some(SccpEvent::FastPauseLapsed(event)));
    }
    transaction.require_storage_admission()?;
    transaction.apply();
    state.require_storage_admission()
}
