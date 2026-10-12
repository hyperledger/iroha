//! Native authenticated message bundles with complete original-owner admission.
//! World records supply leaf inputs, never committee or finality authority. The shared
//! native membership owner binds the exact receipt, block and history paths to original X.

use super::{
    history::funded::SccpHistoryNodeCache,
    membership::{self, NativeProofSource, SccpProofReadError, SelectedKind, SelectedLeaf},
    store,
};
use crate::{state::StateReadOnly, sumeragi::certified_chain::CertifiedBlock};
use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer};
use iroha_sccp::{
    api::SccpMessageProofBundleV1,
    v1::{
        constants::MAX_PAYLOAD_BYTES,
        hashes::{message_id, payload_hash, transfer_leaf},
        payload::SccpTransferPayloadRefV1,
    },
};

/// Move-only bundle retaining every original payload, path and committee allocation.
/// The caller must separately retain source/decoder custody and fund encoded HTTP output.
pub struct RetainedSccpMessageProof {
    bundle: SccpMessageProofBundleV1,
    // The full graph is destroyed before any of its original backing credits are refunded.
    _charges: [AllocationCharge; 4],
}
impl RetainedSccpMessageProof {
    /// Borrow the verified projection without cloning or extracting its graph.
    #[must_use]
    pub fn bundle(&self) -> &SccpMessageProofBundleV1 {
        &self.bundle
    }
}

/// Assemble a message against one already verified native Global committed receipt.
///
/// The caller selects and acquires the original certificate height (record, latest or H).
/// This producer does not assert freshness or turn State rows into consensus authority.
/// A reusable history cache must retain its real enclosing durable owner in addition to its
/// allocation charges; a completed HTTP request lease is not that owner.
///
/// # Errors
/// Refuses missing records, inconsistent coordinates/payload/paths, foreign or genesis
/// authority, certificate verification, and exact original-pool admission/allocation failure.
#[allow(
    unsafe_code,
    reason = "all original Vec allocations move immediately with their charges into a closed immutable body-before-ledger owner"
)]
pub fn message_proof_from_native(
    view: &(impl StateReadOnly + ?Sized),
    requested_id: &[u8; 32],
    native: &CertifiedBlock,
    history_cache: &mut SccpHistoryNodeCache,
    cache_budget: &AllocationBudget,
    budget: &AllocationBudget,
) -> Result<RetainedSccpMessageProof, SccpProofReadError> {
    use SccpProofReadError::{Missing, Source};
    let world = view.world();
    let source = NativeProofSource::new(view, native)?;
    let record =
        store::outbound_messages::get(world, requested_id).ok_or(Missing("outbound message"))?;
    if record.height == 0
        || record.height > native.height()
        || record.payload.len() > MAX_PAYLOAD_BYTES
    {
        return Err(Source("record height or payload size"));
    }
    let payload = SccpTransferPayloadRefV1::decode(&record.payload)?;
    if !payload.is_outbound()
        || payload.target() != Some(record.network)
        || payload.route_revision != record.revision
        || payload.nonce != record.nonce
        || payload.deadline_ms != record.deadline_ms
        || payload.amount != record.amount
    {
        return Err(Source("record payload coordinates"));
    }
    let lane = payload.lane_bytes(view.network_id().as_bytes())?;
    if message_id(&lane, &payload_hash(&record.payload)) != *requested_id {
        return Err(Source("message id"));
    }
    let revision = store::routes::get(world, &record.network)
        .and_then(|route| route.revisions.get(&record.revision))
        .ok_or(Missing("original route revision"))?;
    let leaf = transfer_leaf(requested_id, &revision.destination_word);
    if leaf != record.leaf {
        return Err(Source("transfer leaf destination"));
    }
    let (membership, payload_bytes) = membership::assemble(
        world,
        source,
        SelectedLeaf {
            kind: SelectedKind::Transfer(*requested_id),
            height: record.height,
            index: record.commitment_index,
            hash: leaf,
        },
        history_cache,
        cache_budget,
        budget,
        (
            membership::bytes::<u8>(record.payload.len())?,
            |reservation| {
                let mut payload =
                    ChargedBuffer::from_reservation(record.payload.len(), reservation)?;
                for byte in &record.payload {
                    payload.push_reserved(*byte);
                }
                Ok(payload)
            },
        ),
    )?;
    // SAFETY: all fallible work is complete; the exact payload backing and all membership
    // allocations move immediately with their charges into the immutable response owner.
    let (payload, payload_charge) = unsafe { payload_bytes.into_allocation_parts() };
    let membership::MembershipParts {
        certificate,
        block,
        path,
        charges: [path_charge, history_charge, committee_charge],
    } = membership.into_parts();
    Ok(RetainedSccpMessageProof {
        bundle: SccpMessageProofBundleV1 {
            message_id: *requested_id,
            payload,
            deadline_ms: record.deadline_ms,
            leaf_index: record.commitment_index,
            path,
            block,
            certificate,
        },
        _charges: [
            payload_charge,
            path_charge,
            history_charge,
            committee_charge,
        ],
    })
}

#[cfg(test)]
mod tests;
