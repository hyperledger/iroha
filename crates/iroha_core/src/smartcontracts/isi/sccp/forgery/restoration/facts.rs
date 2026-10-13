//! Private original-pool SCCP source facts reconstructed from authenticated deltas.
//! No decoded World value initializes these stores. A store is local to one scan and
//! remains provisional until that scan reaches its exact captured native tip.
use super::*;
use crate::smartcontracts::isi::sccp::committee_storage::CommitteeStorage;
use crate::state::sccp_forgery_custody::{ForgeryStorageError, OffenceStorage};
use concread::bptree::{
    AllocationDemand, ClonePlanning, NodeCloning, NodeFunding, PlanningError, Prepaid,
};
use iroha_allocation::{AllocationCharge, AllocationReservation};
use mv::storage::{AdmittedBlockError, AdmittedStorageError, AdmittedStoragePolicy, Storage};
use std::alloc::Layout;

pub(super) fn storage(error: AdmittedStorageError) -> Error {
    Error::Storage(ForgeryStorageError::Storage(error))
}
pub(super) fn block(error: AdmittedBlockError<AdmittedStorageError>) -> Error {
    match error {
        AdmittedBlockError::Admission(error) | AdmittedBlockError::Callback(error) => {
            storage(error)
        }
    }
}
// Closed fixed-value map policy: neither key nor value owns a nested allocation.
struct ChunkPolicy(AllocationReservation);
impl NodeFunding for ChunkPolicy {
    type Charge = AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> AllocationCharge {
        self.0
            .try_split(layout)
            .expect("complete original chunk-map node plan")
    }
}
macro_rules! fixed_value {
    ($value:ty) => {
        impl NodeCloning<u64, $value> for ChunkPolicy {
            fn clone_key(&mut self, key: &u64) -> u64 {
                *key
            }
            fn clone_value(&mut self, value: &$value) -> $value {
                *value
            }
        }
        impl ClonePlanning<u64, $value> for ChunkPolicy {
            fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
            fn plan_value(_: &$value, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
        }
    };
}
fixed_value!([u8; 32]);
fixed_value!(Option<[u8; 32]>);
impl AdmittedStoragePolicy for ChunkPolicy {
    fn from_admission(admission: AllocationReservation) -> Self {
        Self(admission)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}

/// Original facts only. Growth follows the retained protocol state, never ordinary height.
pub(super) struct Facts {
    pub(super) generations: CommitteeStorage,
    pub(super) offences: OffenceStorage,
    chunks: Storage<u64, [u8; 32], Prepaid<ChunkPolicy>>,
    pub(super) parameters: Option<SccpParametersV1>,
    pub(super) current: u64,
    pub(super) lc: u64,
    pub(super) maximum: Option<u64>,
    pub(super) derived_maximum: Option<u64>,
    pub(super) open: ChargedBuffer<SccpAnchorV1>,
}
impl Facts {
    pub(super) fn new(budget: &AllocationBudget) -> Result<Self, Error> {
        Ok(Self {
            generations: CommitteeStorage::try_new_admitted(budget.clone()).map_err(storage)?,
            offences: OffenceStorage::try_new_admitted(budget.clone()).map_err(storage)?,
            chunks: Storage::try_new_admitted(budget.clone()).map_err(storage)?,
            parameters: None,
            current: 0,
            lc: 0,
            maximum: None,
            derived_maximum: None,
            open: ChargedBuffer::new(0, budget).map_err(Preparation::from)?,
        })
    }
    pub(super) fn chunk(&self, index: u64) -> Option<[u8; 32]> {
        self.chunks.view().get(&index).copied()
    }
    /// One atomic private edit. The caller advances its delta cursor only after success.
    /// Offences were already installed from the verified Submit in Network order; their
    /// raw delta entries are checked separately, never decoded into authority here.
    pub(super) fn apply(
        &mut self,
        entry: delta::Entry<'_>,
        budget: &AllocationBudget,
    ) -> Result<(), Error> {
        let value = || entry.value.ok_or_else(|| invalid("SCCP cell was deleted"));
        match entry.name {
            b"sccp_parameters" => self.parameters = delta::fixed(value()?)?,
            b"sccp_committee_current" => self.current = delta::fixed(value()?)?,
            b"sccp_liability_clock" => self.lc = delta::fixed(value()?)?,
            b"sccp_forgery_max_generation" => self.maximum = delta::fixed(value()?)?,
            b"sccp_anchor_open" => self.open = anchors(value()?, budget)?,
            b"sccp_committee_generations" => {
                let key: u64 =
                    delta::fixed(entry.key.ok_or_else(|| invalid("generation key missing"))?)?;
                if let Some(bytes) = entry.value {
                    let owner = RetainedSccpGeneration::decode_canonical(bytes, budget)
                        .map_err(generation_error)?;
                    if key != owner.generation {
                        return Err(invalid("original generation key differs"));
                    }
                    self.generations
                        .try_with_admitted_block(|block| {
                            block
                                .try_insert_admitted(key, owner)
                                .map_err(|(_, error)| error)
                        })
                        .map_err(block)?;
                } else {
                    self.generations
                        .try_with_admitted_block(|block| {
                            block.try_remove_admitted(key).map_err(|(_, error)| error)
                        })
                        .map_err(block)?;
                }
            }
            b"sccp_anchor_chunks" => {
                let key: u64 =
                    delta::fixed(entry.key.ok_or_else(|| invalid("chunk key missing"))?)?;
                if let Some(bytes) = entry.value {
                    let root: [u8; 32] = delta::fixed(bytes)?;
                    self.chunks
                        .try_with_admitted_block(|block| {
                            block
                                .try_insert_admitted(key, root)
                                .map_err(|(_, error)| error)
                        })
                        .map_err(block)?;
                } else {
                    self.chunks
                        .try_with_admitted_block(|block| {
                            block.try_remove_admitted(key).map_err(|(_, error)| error)
                        })
                        .map_err(block)?;
                }
            }
            _ => {} // Other canonical writer fields are outside this restoration projection.
        }
        Ok(())
    }
    /// Compare the complete exact current/undo authority cut. Snapshot values are lookup
    /// claims only; all expected values here came from the original authenticated stream.
    pub(super) fn check_cut(&self, state: &State, previous: bool) -> Result<(), Error> {
        macro_rules! scalar {
            ($name:ident, $expected:expr) => {{
                let current = state.world.$name.view();
                let undo = state.world.$name.predecessor_view();
                let actual = if previous {
                    undo.get().as_ref().unwrap_or(current.get())
                } else {
                    current.get()
                };
                if actual != &$expected {
                    return Err(invalid("snapshot SCCP scalar cut differs"));
                }
            }};
        }
        scalar!(sccp_parameters, self.parameters);
        scalar!(sccp_committee_current, self.current);
        scalar!(sccp_liability_clock, self.lc);
        scalar!(sccp_forgery_max_generation, self.derived_maximum);
        let current = state.world.sccp_anchor_open.view();
        let undo = state.world.sccp_anchor_open.predecessor_view();
        let actual = if previous {
            undo.get().as_ref().unwrap_or(current.get())
        } else {
            current.get()
        };
        if actual.as_slice() != self.open.as_slice() {
            return Err(invalid("snapshot open anchors differ"));
        }
        macro_rules! map {
            ($name:ident, $expected:expr) => {{
                let snapshot = state.world.$name.snapshot();
                let expected = $expected.view();
                let rows = snapshot
                    .current()
                    .iter()
                    .filter(|(key, _)| !previous || !snapshot.revert_map().contains_key(*key))
                    .chain(snapshot.revert_map().iter().filter_map(|(key, old)| {
                        previous
                            .then_some(old.as_ref())
                            .flatten()
                            .map(|value| (key, value))
                    }));
                let mut count = 0usize;
                for (key, value) in rows {
                    if expected.get(key) != Some(value) {
                        return Err(invalid("snapshot SCCP map cut differs"));
                    }
                    count = count.checked_add(1).ok_or(Preparation::Invariant)?;
                }
                if count != expected.len() {
                    return Err(invalid("snapshot omits original SCCP map entry"));
                }
            }};
        }
        map!(sccp_committee_generations, self.generations);
        map!(sccp_forgery_offences, self.offences);
        map!(sccp_anchor_chunks, self.chunks);
        if self.maximum != self.derived_maximum {
            return Err(invalid("original offence maximum differs"));
        }
        Ok(())
    }
}
