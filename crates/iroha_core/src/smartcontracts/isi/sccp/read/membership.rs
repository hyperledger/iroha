//! One original native receipt and dense block/history membership kernel for SCCP proofs.
//! Transfer and control producers validate their current leaf semantics before calling this
//! owner. Shared source binding, funding, paths and current certificate verification happen once.

use super::{
    certificate::{NativeCertificateDraft, RetainedSccpCertificate, SccpCertificateReadError},
    history::funded::{self, SccpHistoryNodeCache, SccpHistoryReadError},
    store,
};
use crate::{
    state::{StateReadOnly, WorldReadOnly},
    sumeragi::{certified_chain::CertifiedBlock, crypto::BlsCrypto},
};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    PrepaidBufferError,
};
use iroha_data_model::{
    block::consensus::SumeragiRootScope, bridge::SccpNetworkV1, sccp::control::SccpLeafRefV1,
};
use iroha_sccp::{
    api::{SccpBlockRefV1, SccpCertificateV1},
    v1::{
        constants::MAX_BLOCK_LEAVES,
        hashes::{history_leaf, node},
        history::verify_history_inclusion,
        merkle::verify_block_inclusion,
        payload::PayloadError,
    },
};
use std::alloc::Layout;

/// Precise source, protocol or local-resource refusal of a native proof projection.
#[derive(Debug, thiserror::Error)]
pub enum SccpProofReadError {
    /// A required retained record is absent; absence does not establish pruning.
    #[error("native SCCP proof input missing: {0}")]
    Missing(&'static str),
    /// An input cannot be bound to the selected original native authority.
    #[error("native SCCP proof input differs: {0}")]
    Source(&'static str),
    /// Payload semantic validation failed without allocating a decoded graph.
    #[error(transparent)]
    Payload(#[from] PayloadError),
    /// Current control leaf semantics rejected the exact stored coordinates.
    #[error(transparent)]
    Control(#[from] iroha_sccp::v1::control::ControlLeafError),
    /// Native certificate projection or independent current-suite verification failed.
    #[error(transparent)]
    Certificate(#[from] SccpCertificateReadError),
    /// History acquisition refused or stored history did not reproduce its peaks.
    #[error(transparent)]
    History(#[from] SccpHistoryReadError),
    /// The caller's original pool refused the complete operation before construction.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// A prepaid physical destination allocation failed.
    #[error(transparent)]
    Backing(#[from] PrepaidBufferError),
}

pub(super) fn bytes<T>(count: usize) -> Result<usize, AllocationRefusal> {
    Ok(Layout::array::<T>(count)
        .map_err(|_| AllocationRefusal::DemandOverflow)?
        .size())
}
pub(super) fn sum(left: usize, right: usize) -> Result<usize, AllocationRefusal> {
    left.checked_add(right)
        .ok_or(AllocationRefusal::DemandOverflow)
}

/// Authentication is retained only by borrowing the original opaque receipt.
#[derive(Clone, Copy)]
pub(super) struct NativeProofSource<'a> {
    native: &'a CertifiedBlock,
    certificate: NativeCertificateDraft<'a>,
}
impl<'a> NativeProofSource<'a> {
    pub(super) fn new(
        view: &(impl StateReadOnly + ?Sized),
        native: &'a CertifiedBlock,
    ) -> Result<Self, SccpProofReadError> {
        use SccpProofReadError::Source;
        let certificate = NativeCertificateDraft::new(native)?;
        let x = native.certified_result().header();
        if !x.is_active()
            || native.height() > u64::try_from(view.height()).map_err(|_| Source("view height"))?
        {
            return Err(Source("active certificate must be committed in this view"));
        }
        let offset = native
            .height()
            .checked_sub(1)
            .and_then(|height| usize::try_from(height).ok())
            .ok_or(Source("native block height"))?;
        if view.block_hashes().get(offset).copied() != Some(native.block_hash()) {
            return Err(Source(
                "native receipt is not in the captured committed prefix",
            ));
        }
        let instance = SumeragiRootScope::Global
            .instance_id(
                &BlsCrypto::new(),
                *view.network_id(),
                view.chain_id().as_str(),
            )
            .map_err(|_| Source("view consensus instance"))?;
        if native.commit_qc().is_none_or(|qc| qc.instance != instance) {
            return Err(Source("view network or chain identity"));
        }
        Ok(Self {
            native,
            certificate,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SelectedKind {
    Transfer([u8; 32]),
    Control(SccpNetworkV1, u32, u64),
}
#[derive(Clone, Copy)]
pub(super) struct SelectedLeaf {
    pub(super) kind: SelectedKind,
    pub(super) height: u64,
    pub(super) index: u32,
    pub(super) hash: [u8; 32],
}

pub(super) struct MembershipParts {
    pub(super) certificate: SccpCertificateV1,
    pub(super) block: SccpBlockRefV1,
    pub(super) path: Vec<[u8; 32]>,
    pub(super) charges: [AllocationCharge; 3],
}

pub(super) struct RetainedMembershipProof {
    certificate: RetainedSccpCertificate,
    path: ChargedBuffer<[u8; 32]>,
    history_path: ChargedBuffer<[u8; 32]>,
    height: u64,
    root: [u8; 32],
    count: u32,
    history_index: u64,
}
impl RetainedMembershipProof {
    #[allow(
        unsafe_code,
        reason = "all original buffers move with their exact charges directly into a closed body-before-ledger owner"
    )]
    pub(super) fn into_parts(self) -> MembershipParts {
        // SAFETY: these moves invoke no fallible or panic-capable operation. The destination
        // offers no mutable escape, and its entire graph drops before its original charges.
        let (path, path_charge) = unsafe { self.path.into_allocation_parts() };
        let (history_path, history_charge) = unsafe { self.history_path.into_allocation_parts() };
        let (certificate, committee_charge) = self.certificate.into_parts();
        MembershipParts {
            certificate,
            block: SccpBlockRefV1 {
                height: self.height,
                sccp_root: self.root,
                message_count: self.count,
                history_index: self.history_index,
                history_path,
            },
            path,
            charges: [path_charge, history_charge, committee_charge],
        }
    }
}

/// Join the exact selected current leaf to original X, admitting all request and cache
/// storage before constructing either graph. Extra payload custody joins the same reservation.
pub(super) fn assemble<Extra>(
    world: &(impl WorldReadOnly + ?Sized),
    source: NativeProofSource<'_>,
    selected: SelectedLeaf,
    history_cache: &mut SccpHistoryNodeCache,
    cache_budget: &AllocationBudget,
    budget: &AllocationBudget,
    extra: (
        usize,
        impl FnOnce(&mut AllocationReservation) -> Result<Extra, SccpProofReadError>,
    ),
) -> Result<(RetainedMembershipProof, Extra), SccpProofReadError> {
    use SccpProofReadError::{Missing, Source};
    let NativeProofSource {
        native,
        certificate,
    } = source;
    let (extra_bytes, materialize_extra) = extra;
    let x = native.certified_result().header();
    let commitment = store::block_commitments::get(world, &selected.height)
        .ok_or(Missing("record block commitment"))?;
    if !(1..=MAX_BLOCK_LEAVES).contains(&commitment.message_count)
        || selected.index >= commitment.message_count
        || commitment.root == [0; 32]
    {
        return Err(Source("block commitment geometry"));
    }
    let direct = selected.height == native.height();
    if direct && (commitment.root != x.sccp_root() || commitment.message_count != x.message_count())
    {
        return Err(Source("direct block root or count"));
    }
    if !direct {
        let stored = store::history_leaves::get(world, &commitment.history_index)
            .ok_or(Missing("record history leaf"))?;
        if *stored
            != (
                selected.height,
                history_leaf(selected.height, &commitment.root, commitment.message_count),
            )
        {
            return Err(Source("record history coordinates"));
        }
    }
    let source = funded::WorldHistory(world);
    let history = if direct {
        None
    } else {
        Some(history_cache.draft(
            &source,
            commitment.history_index,
            x.history_size(),
            cache_budget,
        )?)
    };
    let count =
        usize::try_from(commitment.message_count).map_err(|_| AllocationRefusal::DemandOverflow)?;
    let path_len = funded::path_len(
        u64::from(selected.index),
        u64::from(commitment.message_count),
    );
    let mut demand = sum(certificate.demand()?, extra_bytes)?;
    for next in [
        bytes::<[u8; 32]>(count)?,
        bytes::<[u8; 32]>(path_len)?,
        history
            .as_ref()
            .map_or(Ok(0), |history| history.request_demand())?,
    ] {
        demand = sum(demand, next)?;
    }
    // No graph above was cloned or allocated. Admit both original owners before construction.
    let cache_demand = history
        .as_ref()
        .map_or(Ok(0), |history| history.cache_demand())?;
    let (mut reservation, mut cache_reservation) =
        funded::reserve_operation(budget, demand, cache_budget, cache_demand)?;
    let certificate = certificate.materialize(&mut reservation)?;
    let mut hashes = ChargedBuffer::from_reservation(count, &mut reservation)?;
    let mut path = ChargedBuffer::from_reservation(path_len, &mut reservation)?;
    let extra = materialize_extra(&mut reservation)?;
    for ((height, index), reference) in
        store::block_leaves::range(world, (selected.height, 0)..=(selected.height, u32::MAX))
    {
        if *height != selected.height
            || usize::try_from(*index).ok() != Some(hashes.as_slice().len())
            || hashes.as_slice().len() >= count
        {
            return Err(Source("dense leaf coordinates"));
        }
        let (stored_height, stored_index, hash) = match reference {
            SccpLeafRefV1::Transfer(transfer) => {
                let other = store::outbound_messages::get(world, &transfer.message_id)
                    .ok_or(Missing("block transfer leaf"))?;
                if *index == selected.index
                    && selected.kind != SelectedKind::Transfer(transfer.message_id)
                {
                    return Err(Source("selected transfer leaf"));
                }
                (other.height, other.commitment_index, other.leaf)
            }
            SccpLeafRefV1::Control(control) => {
                if *index == selected.index
                    && selected.kind
                        != SelectedKind::Control(
                            control.network,
                            control.revision,
                            control.control_nonce,
                        )
                {
                    return Err(Source(
                        if matches!(selected.kind, SelectedKind::Transfer(_)) {
                            "selected leaf is a control"
                        } else {
                            "selected control leaf"
                        },
                    ));
                }
                // Sibling hashes remain opaque; the selected producer alone interprets its
                // current record. Both kinds share this exact authenticated graph walk.
                let other = store::control_messages::get(
                    world,
                    &(control.network, control.revision, control.control_nonce),
                )
                .ok_or(Missing("block control sibling"))?;
                (other.height, other.commitment_index, other.leaf)
            }
        };
        if stored_height != *height || stored_index != *index {
            return Err(Source("leaf record coordinates"));
        }
        hashes.push_reserved(hash);
    }
    if hashes.as_slice().len() != count
        || hashes.as_slice().get(selected.index as usize) != Some(&selected.hash)
    {
        return Err(Source("leaf count or selected hash"));
    }
    let (mut width, mut position) = (count, selected.index as usize);
    while width > 1 {
        if position % 2 == 1 {
            path.push_reserved(hashes.as_slice()[position - 1]);
        } else if position + 1 < width {
            path.push_reserved(hashes.as_slice()[position + 1]);
        }
        let level = hashes.as_mut_slice();
        for parent in 0..width.div_ceil(2) {
            let child = parent * 2;
            level[parent] = if child + 1 < width {
                node(&level[child], &level[child + 1])
            } else {
                level[child]
            };
        }
        position >>= 1;
        width = width.div_ceil(2);
    }
    if hashes.as_slice()[0] != commitment.root {
        return Err(Source("leaf graph root"));
    }
    verify_block_inclusion(
        &selected.hash,
        selected.index,
        commitment.message_count,
        path.as_slice(),
        &commitment.root,
    )
    .map_err(|_| Source("independent block path verification"))?;
    let history_path = if let Some(history) = history {
        let acquired = history.materialize_checked(
            &mut reservation,
            &mut cache_reservation,
            Some((
                x.history_root(),
                history_leaf(selected.height, &commitment.root, commitment.message_count),
            )),
        )?;
        if acquired.root() != x.history_root() {
            return Err(Source("history root differs from original X"));
        }
        verify_history_inclusion(
            &history_leaf(selected.height, &commitment.root, commitment.message_count),
            commitment.history_index,
            x.history_size(),
            acquired.path(),
            &x.history_root(),
        )
        .map_err(|_| Source("independent history path verification"))?;
        acquired.into_buffer()
    } else {
        ChargedBuffer::from_reservation(0, &mut reservation)?
    };
    Ok((
        RetainedMembershipProof {
            certificate,
            path,
            history_path,
            height: selected.height,
            root: commitment.root,
            count: commitment.message_count,
            history_index: if direct { 0 } else { commitment.history_index },
        },
        extra,
    ))
}
