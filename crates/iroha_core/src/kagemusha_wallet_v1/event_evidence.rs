//! Deterministic pre-seal retention of ordinary Load event inclusion paths.
//!
//! These rows contain no QC, checkpoint, signer or finality authority. They are
//! written before the World root is sealed, depend only on the original event
//! stream and height, and are rolled back with that same World overlay.

use super::{Digest, Error, Result, storage};
use crate::{execution_attempt::ExecutionDeferred, state::WorldBlock};
use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBuffer, ChargedBufferError};
use iroha_crypto::{Hash, HashOf, MerkleError, MerkleProof, MerkleTree, MerkleTreeCommitment};
use iroha_data_model::{
    events::{
        EventBox,
        data::{DataEvent, kagemusha::KagemushaLoadCommittedV1},
    },
    kagemusha::{KagemushaWalletLedgerKeyV1, kagemusha_wallet_is_canonical_field_v1},
};
use mv::storage::StorageReadOnly as _;
use norito::{Decode, Encode};
use std::{io::Cursor, num::NonZeroU64};

#[cfg(test)]
mod tests;

pub(super) const KIND: u8 = 15;
pub(super) const CAP: usize = 4096;
const DEPTH: usize = 32;

/// Counted inclusion data retained from one exact pre-seal event stream.
///
/// This is data only. Callers must join it to independently verified native
/// finality at `height` before it can authenticate a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::KagemushaLoadEventPathV1")]
pub struct KagemushaLoadEventPathV1 {
    height: u64,
    receipt_digest: Digest,
    root: HashOf<MerkleTree<EventBox>>,
    count: NonZeroU64,
    index: u32,
    depth: u8,
    siblings: [Option<HashOf<EventBox>>; DEPTH],
}

impl KagemushaLoadEventPathV1 {
    /// Original ordinary execution height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// Canonical original receipt identity.
    #[must_use]
    pub const fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }
    /// Root and count as one indivisible candidate commitment.
    #[must_use]
    pub const fn commitment(&self) -> MerkleTreeCommitment<EventBox> {
        MerkleTreeCommitment::new(self.root, self.count)
    }
    /// Materialize at most 32 siblings without an unbounded allocation.
    ///
    /// # Errors
    /// Refuses invalid depth or unavailable path backing.
    pub fn proof(&self) -> Result<MerkleProof<EventBox>> {
        let depth = usize::from(self.depth);
        if depth > DEPTH {
            return Err(Error::Binding);
        }
        let mut siblings = Vec::new();
        siblings
            .try_reserve_exact(depth)
            .map_err(|_| Error::Unavailable)?;
        siblings.extend_from_slice(&self.siblings[..depth]);
        Ok(MerkleProof::from_audit_path(self.index, siblings))
    }
    pub(super) fn validate(&self, selected: &KagemushaWalletLedgerKeyV1) -> Result<()> {
        let depth = usize::from(self.depth);
        if self.height < 2
            || self.receipt_digest == [0; 32]
            || !kagemusha_wallet_is_canonical_field_v1(&self.receipt_digest)
            || depth > DEPTH
            || self.count.get() > (1_u64 << 32)
            || self.siblings[depth..].iter().any(Option::is_some)
            || key(self.receipt_digest) != *selected
        {
            return Err(Error::Binding);
        }
        let event = EventBox::Data(
            DataEvent::KagemushaLoadCommitted(KagemushaLoadCommittedV1 {
                receipt_digest: self.receipt_digest,
            })
            .into(),
        );
        let hash = HashOf::try_new(&event).map_err(|_| Error::Binding)?;
        if !self.proof()?.verify(&hash, &self.commitment()) {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

pub(super) fn key(digest: Digest) -> KagemushaWalletLedgerKeyV1 {
    storage::key(
        KIND,
        *Hash::new(b"iroha:kagemusha:ordinary-load-event-path:v1\0").as_ref(),
        digest,
    )
}

/// Preserve real local refusal separately from invalid retained event data.
#[derive(Debug)]
pub(crate) enum PreparationError {
    Invalid(String),
    Deferred(ExecutionDeferred),
}
impl From<AllocationRefusal> for PreparationError {
    fn from(error: AllocationRefusal) -> Self {
        Self::Deferred(error.into())
    }
}
fn allocation(error: ChargedBufferError) -> PreparationError {
    match error {
        ChargedBufferError::Admission(original) => original.into(),
        ChargedBufferError::Allocator { .. } => {
            PreparationError::Deferred(ivm::ExecutionDeferral::AllocationUnavailable.into())
        }
    }
}
fn invalid(error: impl ToString) -> PreparationError {
    PreparationError::Invalid(error.to_string())
}
fn codec(error: norito::Error) -> PreparationError {
    match crate::execution_attempt::norito_decode_attempt_error(error, |error| error.to_string()) {
        crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
            PreparationError::Deferred(original)
        }
        crate::execution_attempt::ExecutionAttemptError::Rejected(reason) => {
            PreparationError::Invalid(reason)
        }
    }
}
struct PreparedRow {
    key: KagemushaWalletLedgerKeyV1,
    bytes: Vec<u8>,
}

fn load_digest(event: &EventBox) -> Option<Digest> {
    match event {
        EventBox::Data(data) => match data.as_ref() {
            DataEvent::KagemushaLoadCommitted(load) => Some(load.receipt_digest),
            _ => None,
        },
        _ => None,
    }
}

/// Capture exactly the pre-seal stream, with one prepaid tree and bounded rows.
///
/// Must run after the final deterministic event-producing effects and before
/// witness/World-root capture. No publication event may have been appended.
pub(crate) fn retain(
    world: &mut WorldBlock<'_>,
    height: u64,
    budget: &AllocationBudget,
) -> std::result::Result<(), PreparationError> {
    let events = world.pending_external_events();
    let loads = events
        .iter()
        .filter(|event| load_digest(event).is_some())
        .count();
    if loads == 0 {
        return Ok(());
    }
    if height < 2 || u64::try_from(events.len()).map_err(invalid)? > (1_u64 << 32) {
        return Err(invalid(
            "Load event geometry exceeds the canonical proof index",
        ));
    }
    let tree_bytes = MerkleTree::<EventBox>::application_node_allocation_bytes(events.len())
        .map_err(|_| AllocationRefusal::DemandOverflow)?;
    let bytes = loads
        .checked_mul(CAP)
        .and_then(|rows| rows.checked_add(tree_bytes))
        .ok_or(AllocationRefusal::DemandOverflow)?;
    // Declared before every covered backing, so the actual allocations drop first.
    let _backing = budget.try_reserve_bytes(bytes)?;
    let mut rows = ChargedBuffer::<PreparedRow>::new(loads, budget).map_err(allocation)?;
    // Preserve a source codec refusal before entering the infallible hash iterator.
    // The finite leaf backing is charged independently of the tree node backing.
    let mut leaves = ChargedBuffer::new(events.len(), budget).map_err(allocation)?;
    for event in events {
        leaves.push_reserved(HashOf::try_new(event).map_err(codec)?);
    }
    let tree =
        MerkleTree::try_from_typed_leaves(leaves.as_slice().iter().copied()).map_err(|error| {
            match error {
                MerkleError::AllocationUnavailable => {
                    PreparationError::Deferred(ivm::ExecutionDeferral::AllocationUnavailable.into())
                }
                other => invalid(other),
            }
        })?;
    drop(leaves);
    let commitment = tree
        .commitment()
        .ok_or_else(|| invalid("Load event stream is empty"))?;
    for (index, event) in events.iter().enumerate() {
        let Some(receipt_digest) = load_digest(event) else {
            continue;
        };
        let index = u32::try_from(index).map_err(invalid)?;
        let path = tree
            .proof_siblings(index)
            .ok_or_else(|| invalid("Load event index differs"))?;
        let mut record = KagemushaLoadEventPathV1 {
            height,
            receipt_digest,
            root: *commitment.root(),
            count: commitment.leaf_count(),
            index,
            depth: u8::try_from(path.len()).map_err(invalid)?,
            siblings: [None; DEPTH],
        };
        if usize::from(record.depth) > DEPTH {
            return Err(invalid("Load event path exceeds 32 levels"));
        }
        for (slot, sibling) in record.siblings.iter_mut().zip(path) {
            *slot = sibling;
        }
        let selected = key(receipt_digest);
        record.validate(&selected).map_err(invalid)?;
        let measured = norito::canonical_frame_len(&record).map_err(codec)?;
        if measured > CAP {
            return Err(invalid("Load event path frame exceeds its fixed bound"));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(measured).map_err(|_| {
            PreparationError::Deferred(ivm::ExecutionDeferral::AllocationUnavailable.into())
        })?;
        bytes.resize(measured, 0);
        let mut writer = Cursor::new(bytes.as_mut_slice());
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        norito::serialize_into(&mut writer, &record, norito::Compression::None).map_err(codec)?;
        if writer.position() != measured as u64 {
            return Err(invalid("Load event frame extent differs"));
        }
        if let Some(prior) = world.kagemusha_wallet_ledger.get(&selected) {
            if prior != &bytes {
                return Err(invalid(
                    "Load event identity already belongs to another stream",
                ));
            }
        }
        rows.push_reserved(PreparedRow {
            key: selected,
            bytes,
        });
    }
    rows.as_mut_slice().sort_unstable_by_key(|row| row.key);
    if rows
        .as_slice()
        .windows(2)
        .any(|pair| pair[0].key == pair[1].key)
    {
        return Err(invalid(
            "one original receipt occurs twice in the event stream",
        ));
    }
    for row in rows.as_mut_slice() {
        world
            .kagemusha_wallet_ledger
            .insert(row.key, std::mem::take(&mut row.bytes));
    }
    Ok(())
}
