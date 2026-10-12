//! Native proof projection of the current 199-byte control record.
//! The original Global receipt supplies all finality authority. Record cause fields are
//! committed data, not permission to enact an effect or recreate a governance certificate.

use super::{
    history::funded::SccpHistoryNodeCache,
    membership::{self, NativeProofSource, SccpProofReadError, SelectedKind, SelectedLeaf},
    store,
};
use crate::{state::StateReadOnly, sumeragi::certified_chain::CertifiedBlock};
use iroha_allocation::{AllocationBudget, AllocationCharge};
use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::{
    api::SccpControlProofBundleV1,
    v1::control::{ControlLeafV1, control_leaf},
};

/// Immutable control bundle retaining its original paths and committee until final drop.
pub struct RetainedSccpControlProof {
    bundle: SccpControlProofBundleV1,
    _charges: [AllocationCharge; 3],
}
impl RetainedSccpControlProof {
    /// Borrow the verified projection without separating its graph from original custody.
    #[must_use]
    pub fn bundle(&self) -> &SccpControlProofBundleV1 {
        &self.bundle
    }
}

/// Bind one current control record to an already verified native Global receipt.
/// The caller acquires and selects the certificate height; freshness and destination policy
/// remain verifier responsibilities. Missing input alone never establishes retention pruning.
///
/// # Errors
/// Refuses absent/malformed records, substituted cause or destination, foreign native authority,
/// block/history inconsistency and original typed request/cache admission or allocation failure.
pub fn control_proof_from_native(
    view: &(impl StateReadOnly + ?Sized),
    requested: (SccpNetworkV1, u32, u64),
    native: &CertifiedBlock,
    history_cache: &mut SccpHistoryNodeCache,
    cache_budget: &AllocationBudget,
    budget: &AllocationBudget,
) -> Result<RetainedSccpControlProof, SccpProofReadError> {
    use SccpProofReadError::{Missing, Source};
    let source = NativeProofSource::new(view, native)?;
    let world = view.world();
    let (network, revision, control_nonce) = requested;
    let record =
        store::control_messages::get(world, &requested).ok_or(Missing("control record"))?;
    if !record.has_valid_shape() || record.height > native.height() {
        return Err(Source("control record shape or height"));
    }
    let route = store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .ok_or(Missing("original route revision"))?;
    let leaf = control_leaf(
        view.network_id().as_bytes(),
        network,
        &route.destination_word,
        &ControlLeafV1 {
            route_revision: revision,
            control_nonce,
            track: record.track,
            parliament_paused: u8::from(record.parliament_paused),
            fast_pause_until_ms: record.fast_pause_until_ms,
            certificate_id: record.certificate_id,
            effect_hash: record.effect_hash,
        },
    )?;
    if leaf != record.leaf {
        return Err(Source("control leaf cause or destination"));
    }
    let (membership, ()) = membership::assemble(
        world,
        source,
        SelectedLeaf {
            kind: SelectedKind::Control(network, revision, control_nonce),
            height: record.height,
            index: record.commitment_index,
            hash: leaf,
        },
        history_cache,
        cache_budget,
        budget,
        (0, |_| Ok(())),
    )?;
    let membership::MembershipParts {
        certificate,
        block,
        path,
        charges,
    } = membership.into_parts();
    Ok(RetainedSccpControlProof {
        bundle: SccpControlProofBundleV1 {
            network,
            revision,
            control_nonce,
            track: record.track,
            parliament_paused: record.parliament_paused,
            fast_pause_until_ms: record.fast_pause_until_ms,
            certificate_id: record.certificate_id,
            effect_hash: record.effect_hash,
            leaf_index: record.commitment_index,
            path,
            block,
            certificate,
        },
        _charges: charges,
    })
}

#[cfg(test)]
mod tests;
