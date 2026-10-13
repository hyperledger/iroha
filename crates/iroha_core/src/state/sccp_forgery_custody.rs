//! Original-pool immutable offence keys and permanent SCCP deduplication storage.
//!
//! The key wire/order is exactly `(generation, lane, AccountId)`. Shared custody is
//! local only. Neither a decoded key nor inserting it authenticates an offence.

use concread::bptree::{
    AllocationDemand, ClonePlanning, NodeCloning, NodeFunding, PlanningError, Prepaid,
};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationReservation, ChargedBuffer, ChargedShared,
    RetainedPayload,
};
use iroha_data_model::account::AccountId;
use iroha_model_base::topology::LaneId;
use mv::storage::AdmittedStorageError;
use norito::core::{Encoder, SerializePayload};
use std::{alloc::Layout, cmp::Ordering, fmt, mem::ManuallyDrop, ops::Deref};

/// Exact protocol deduplication key; activation is retained in the evidence, not this key.
pub type CanonicalOffenceKey = (u64, LaneId, AccountId);
/// Original finite-pool/decoder refusal, distinct from an invalid snapshot claim.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ForgeryStorageError {
    /// Original map or payload admission.
    #[error(transparent)]
    Storage(#[from] AdmittedStorageError),
    /// Exact decoder resource origin.
    #[error("SCCP offence decode resources: {0}")]
    Codec(norito::core::DecodeResourceError),
    /// Invalid key, record or custody join.
    #[error("invalid SCCP offence storage claim")]
    Invalid,
}
fn codec(e: norito::core::Error) -> ForgeryStorageError {
    e.decode_resource_error()
        .map_or(ForgeryStorageError::Invalid, ForgeryStorageError::Codec)
}
fn overflow() -> ForgeryStorageError {
    AdmittedStorageError::Allocation(iroha_allocation::AllocationRefusal::DemandOverflow).into()
}
fn prepaid(e: iroha_allocation::PrepaidBufferError) -> ForgeryStorageError {
    match e {
        iroha_allocation::PrepaidBufferError::Reservation(_) => ForgeryStorageError::Invalid,
        iroha_allocation::PrepaidBufferError::Allocation(
            iroha_allocation::ChargedBufferError::Admission(e),
        ) => AdmittedStorageError::Allocation(e).into(),
        iroha_allocation::PrepaidBufferError::Allocation(
            iroha_allocation::ChargedBufferError::Allocator { requested_bytes },
        ) => ForgeryStorageError::Codec(norito::core::DecodeResourceError::AllocationFailed {
            bytes: u64::try_from(requested_bytes).unwrap_or(u64::MAX),
        }),
    }
}
fn shared(e: iroha_allocation::PrepaidSharedError) -> ForgeryStorageError {
    match e {
        iroha_allocation::PrepaidSharedError::Reservation(_) => ForgeryStorageError::Invalid,
        iroha_allocation::PrepaidSharedError::Allocator { requested_bytes } => {
            ForgeryStorageError::Codec(norito::core::DecodeResourceError::AllocationFailed {
                bytes: u64::try_from(requested_bytes).unwrap_or(u64::MAX),
            })
        }
    }
}
enum KeyGraph {
    Copied(RetainedPayload<CanonicalOffenceKey>),
    Decoded(DecodedKey),
}
struct DecodedKey {
    key: ManuallyDrop<CanonicalOffenceKey>,
    allowance: ManuallyDrop<AllocationReservation>,
}
impl Drop for DecodedKey {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: immutable private graph retires before its original allowance.
        unsafe {
            ManuallyDrop::drop(&mut self.key);
            ManuallyDrop::drop(&mut self.allowance);
        }
    }
}
impl KeyGraph {
    fn get(&self) -> &CanonicalOffenceKey {
        match self {
            Self::Copied(p) => p.get(),
            Self::Decoded(p) => &p.key,
        }
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        match self {
            Self::Copied(p) => p.belongs_to(budget),
            Self::Decoded(p) => p.allowance.belongs_to(budget),
        }
    }
}
/// Immutable shared canonical key; map/touch/undo clones allocate no account graph.
pub struct OffenceKey(ChargedShared<KeyGraph>);
impl Clone for OffenceKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Deref for OffenceKey {
    type Target = CanonicalOffenceKey;
    fn deref(&self) -> &Self::Target {
        self.0.get()
    }
}
impl fmt::Debug for OffenceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.deref().fmt(f)
    }
}
impl PartialEq for OffenceKey {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}
impl Eq for OffenceKey {}
impl PartialOrd for OffenceKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OffenceKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deref().cmp(other.deref())
    }
}
impl OffenceKey {
    /// Original generation component of the canonical tuple.
    pub fn generation(&self) -> u64 {
        self.deref().0
    }
    /// Check the shared control and account graph against the actual original map pool.
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget) && self.0.belongs_to_graph(budget)
    }
    /// Fund a canonical query/insertion key before copying any account allocation.
    pub(crate) fn try_copy(
        generation: u64,
        lane: LaneId,
        account: &AccountId,
        budget: &AllocationBudget,
    ) -> Result<Self, ForgeryStorageError> {
        if generation == 0 {
            return Err(ForgeryStorageError::Invalid);
        }
        let (mut count, mut bytes, mut overflowed) = (0usize, 0usize, false);
        account
            .for_each_admission_clone_layout(|layout| {
                match (count.checked_add(1), bytes.checked_add(layout.size())) {
                    (Some(n), Some(b)) => {
                        count = n;
                        bytes = b;
                    }
                    _ => overflowed = true,
                }
            })
            .map_err(codec)?;
        if overflowed {
            return Err(overflow());
        }
        bytes = bytes
            .checked_add(
                Layout::array::<AllocationCharge>(count)
                    .map_err(|_| overflow())?
                    .size(),
            )
            .and_then(|b| b.checked_add(ChargedShared::<KeyGraph>::allocation_layout().size()))
            .ok_or_else(overflow)?;
        let mut reservation = budget
            .try_reserve_bytes(bytes)
            .map_err(AdmittedStorageError::Allocation)?;
        // Ledger declared first: every partial copied graph drops before its charge.
        let mut ledger =
            ChargedBuffer::from_reservation(count, &mut reservation).map_err(prepaid)?;
        let shell = ChargedShared::reserve_from(&mut reservation).map_err(shared)?;
        let mut mismatch = false;
        account
            .for_each_admission_clone_layout(|layout| match reservation.try_split(layout) {
                Ok(c) => ledger.push_reserved(c),
                Err(_) => mismatch = true,
            })
            .map_err(codec)?;
        if mismatch {
            return Err(ForgeryStorageError::Invalid);
        }
        let key = (
            generation,
            lane,
            account.try_clone_for_admission().map_err(codec)?,
        );
        // SAFETY: exact immutable account graph and all its original charges move together.
        #[allow(unsafe_code)]
        let key = unsafe { RetainedPayload::try_new(key, ledger, budget) }.map_err(
            |(key, ledger, _)| {
                drop(key);
                drop(ledger);
                ForgeryStorageError::Invalid
            },
        )?;
        Ok(Self(shell.initialize(KeyGraph::Copied(key))))
    }
    /// Decode the exact canonical key under the original map pool; no authority is inferred.
    pub(crate) fn decode_snapshot_hex(
        source: &str,
        budget: &AllocationBudget,
    ) -> Result<Self, ForgeryStorageError> {
        use norito::codec::DecodeAll as _;
        if source.len() % 2 != 0 {
            return Err(ForgeryStorageError::Invalid);
        }
        let mut bytes = ChargedBuffer::new(source.len() / 2, budget)
            .map_err(|e| prepaid(iroha_allocation::PrepaidBufferError::Allocation(e)))?;
        let nibble = |b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        for pair in source.as_bytes().chunks_exact(2) {
            bytes.push_reserved(
                (nibble(pair[0]).ok_or(ForgeryStorageError::Invalid)? << 4)
                    | nibble(pair[1]).ok_or(ForgeryStorageError::Invalid)?,
            );
        }
        let controls = ChargedShared::<KeyGraph>::allocation_layout()
            .size()
            .checked_add(norito::core::DecodeBudgetContext::allocation_layout().size())
            .ok_or_else(overflow)?;
        let mut controls = budget
            .try_reserve_bytes(controls)
            .map_err(AdmittedStorageError::Allocation)?;
        let shell = ChargedShared::reserve_from(&mut controls).map_err(shared)?;
        let available = budget.limit_bytes().saturating_sub(budget.reserved_bytes());
        let allowance = budget
            .try_reserve_bytes(available)
            .map_err(AdmittedStorageError::Allocation)?;
        let limits =
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, available, usize::MAX);
        let context = norito::core::DecodeBudgetContext::from_reservation(limits, &mut controls)
            .map_err(shared)?;
        let key = context
            .with(|| CanonicalOffenceKey::decode_all(&mut bytes.as_slice()))
            .map_err(codec)?;
        let mut key = DecodedKey {
            key: ManuallyDrop::new(key),
            allowance: ManuallyDrop::new(allowance),
        };
        norito::codec::verify_exact_payload(&*key.key, bytes.as_slice()).map_err(codec)?;
        if key.key.0 == 0 {
            return Err(ForgeryStorageError::Invalid);
        }
        let used = usize::try_from(context.consumed_allocated_bytes()).map_err(|_| overflow())?;
        let retained = key
            .allowance
            .try_partition_bytes(used)
            .map_err(|_| ForgeryStorageError::Invalid)?;
        drop(std::mem::replace(&mut *key.allowance, retained));
        Ok(Self(shell.initialize(KeyGraph::Decoded(key))))
    }
}
// Distinct name avoids resolving ChargedShared's own control-pool method twice.
impl KeyGraph {
    fn belongs_to_graph(&self, budget: &AllocationBudget) -> bool {
        self.belongs_to(budget)
    }
}
impl SerializePayload for OffenceKey {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.deref().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.deref().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.deref().encoded_len_exact()
    }
}
impl norito::NoritoSchema for OffenceKey {
    fn nominal_name() -> String {
        <CanonicalOffenceKey as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <CanonicalOffenceKey as norito::NoritoSchema>::frame_name()
    }
}
/// Node admission never copies a nested account: all key clones retain its original handle.
pub struct OffencePolicy(AllocationReservation);
impl NodeFunding for OffencePolicy {
    type Charge = AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> AllocationCharge {
        self.0
            .try_split(layout)
            .expect("complete original offence node plan")
    }
}
macro_rules! policy {
    ($value:ty) => {
        impl NodeCloning<OffenceKey, $value> for OffencePolicy {
            fn clone_key(&mut self, k: &OffenceKey) -> OffenceKey {
                k.clone()
            }
            fn clone_value(&mut self, v: &$value) -> $value {
                *v
            }
        }
        impl ClonePlanning<OffenceKey, $value> for OffencePolicy {
            fn plan_key(_: &OffenceKey, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
            fn plan_value(_: &$value, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
        }
    };
}
policy!([u8; 32]);
policy!(Option<[u8; 32]>);
impl mv::storage::AdmittedStoragePolicy for OffencePolicy {
    fn from_admission(a: AllocationReservation) -> Self {
        Self(a)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}
/// Exact original-pool map mode, with no production Untracked fallback.
pub type OffenceMode = Prepaid<OffencePolicy>;
/// Permanent offence to exact raw evidence-id mapping, including original undo.
pub type OffenceStorage = mv::storage::Storage<OffenceKey, [u8; 32], OffenceMode>;

#[cfg(test)]
#[path = "sccp_forgery_custody/tests.rs"]
mod tests;

/// Admit the scalar cell's original current and undo controls; absent is not generation zero.
pub(crate) fn initialize_max(
    current: Option<u64>,
    previous: Option<Option<u64>>,
    budget: &AllocationBudget,
) -> Result<mv::cell::Cell<Option<u64>, AllocationCharge>, AdmittedStorageError> {
    mv::cell::CellInitialization::try_reserve(budget)
        .map(|owner| owner.initialize(current, previous))
        .map_err(super::scalar_cell_custody::admission_error)
}
