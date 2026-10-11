//! Original five-source contract custody, ten-field frozen context and held encoding outcomes.
//! Native reader controls and the canonical encoder retain their own funding obligations.
use super::contract_relation::{CheckedStrategy, NativeSources, TriggerContractError};
use super::*;
use crate::state::authority_registry::leaf::{
    CanonicalTableLeafSet, CanonicalTablePairedSnapshot, LeafError, LeafLimits,
};
use iroha_allocation::AllocationBudget;
use mv::storage::{CommittedStorageView, FrozenStorageImages};

/// All five native original read owners, retained through check, encoding and final probes.
/// Source readers drop before the fixed counter's original-pool refund notification.
pub(crate) struct CheckedContracts<'set> {
    set: &'set Set,
    budget: &'set AllocationBudget,
    #[cfg(test)]
    probes: std::cell::Cell<[usize; 5]>,
    data: CommittedStorageView<'set, TriggerId, LoadedAction<DataEventFilter>>,
    pipeline: CommittedStorageView<'set, TriggerId, LoadedAction<PipelineEventFilterBox>>,
    time: CommittedStorageView<'set, TriggerId, LoadedAction<TimeEventFilter>>,
    by_call: CommittedStorageView<'set, TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
    contracts: CommittedStorageView<'set, HashOf<IvmBytecode>, IvmBytecodeEntry>,
    strategy: Option<CheckedStrategy>,
}
#[path = "set_contract_capture/actions.rs"]
mod actions;
pub(crate) use actions::CheckedActions;

impl<'set> CheckedContracts<'set> {
    /// Retain the same five actual original readers before any semantic strategy runs.
    fn retain(
        set: &'set Set,
        budget: &'set AllocationBudget,
    ) -> Result<Self, TriggerContractError> {
        Ok(Self {
            set,
            budget,
            #[cfg(test)]
            probes: std::cell::Cell::new([0; 5]),
            data: set.data_triggers.try_committed_view_nonblocking()?,
            pipeline: set.pipeline_triggers.try_committed_view_nonblocking()?,
            time: set.time_triggers.try_committed_view_nonblocking()?,
            by_call: set.by_call_triggers.try_committed_view_nonblocking()?,
            contracts: set.contracts.try_committed_view_nonblocking()?,
            strategy: None,
        })
    }
    /// Retain and validate both actual published images before encoding any row.
    pub(crate) fn capture(
        set: &'set Set,
        max_work: u64,
        budget: &'set AllocationBudget,
    ) -> Result<Self, TriggerContractError> {
        let mut checked = Self::retain(set, budget)?;
        let result = (|| {
            let sources = NativeSources {
                data: &checked.data,
                pipeline: &checked.pipeline,
                time: &checked.time,
                by_call: &checked.by_call,
                contracts: &checked.contracts,
            };
            checked.strategy = Some(CheckedStrategy::prepare(&sources, max_work, budget)?);
            checked
                .strategy
                .as_mut()
                .expect("prepared original counter")
                .validate(&sources)
        })();
        // Every original Result is materialized, even on source/work/allocation/codec failure.
        let current = checked.matches_current();
        if !current? {
            return Err(mv::PublicationPreparationError::Changed.into());
        }
        result?;
        Ok(checked)
    }
    /// Materialize all five native probes before propagating any first refusal.
    pub(crate) fn matches_current(&self) -> Result<bool, TriggerContractError> {
        let data = self.data.try_matches_current(&self.set.data_triggers);
        #[cfg(test)]
        {
            let mut probes = self.probes.get();
            probes[0] += 1;
            self.probes.set(probes);
        }
        let pipeline = self
            .pipeline
            .try_matches_current(&self.set.pipeline_triggers);
        #[cfg(test)]
        {
            let mut probes = self.probes.get();
            probes[1] += 1;
            self.probes.set(probes);
        }
        let time = self.time.try_matches_current(&self.set.time_triggers);
        #[cfg(test)]
        {
            let mut probes = self.probes.get();
            probes[2] += 1;
            self.probes.set(probes);
        }
        let by_call = self.by_call.try_matches_current(&self.set.by_call_triggers);
        #[cfg(test)]
        {
            let mut probes = self.probes.get();
            probes[3] += 1;
            self.probes.set(probes);
        }
        let contracts = self.contracts.try_matches_current(&self.set.contracts);
        #[cfg(test)]
        {
            let mut probes = self.probes.get();
            probes[4] += 1;
            self.probes.set(probes);
        }
        let data = data?;
        let pipeline = pipeline?;
        let time = time?;
        let by_call = by_call?;
        let contracts = contracts?;
        Ok(data && pipeline && time && by_call && contracts)
    }
    /// Encode the exact checked original current rows while the counter and native owners live.
    pub(crate) fn encode(
        &mut self,
        limits: LeafLimits,
    ) -> Result<CanonicalTablePairedSnapshot, LeafError> {
        let rows = self
            .strategy
            .as_mut()
            .expect("checked original counter")
            .encoding_rows(&self.contracts)?;
        CanonicalTableLeafSet::paired_semantic_table_from_rows(
            "triggers.contracts",
            "iroha:state:trigger-contract-bytecode:v1",
            limits,
            self.budget,
            rows,
            BorrowedWorldContract::from,
        )
    }
}
struct FrozenContracts<'frozen> {
    data: FrozenStorageImages<'frozen, TriggerId, LoadedAction<DataEventFilter>>,
    pipeline: FrozenStorageImages<'frozen, TriggerId, LoadedAction<PipelineEventFilterBox>>,
    time: FrozenStorageImages<'frozen, TriggerId, LoadedAction<TimeEventFilter>>,
    by_call: FrozenStorageImages<'frozen, TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
    contracts: FrozenStorageImages<'frozen, HashOf<IvmBytecode>, IvmBytecodeEntry>,
    // The contract-only engine adds no predicates for these real context owners.
    // The action child borrows all ten for its derived-index consistency relation.
    _ids: FrozenStorageImages<'frozen, TriggerId, TriggeringEventType>,
    _active_data: FrozenStorageImages<'frozen, TriggerId, ()>,
    _active_pipeline: FrozenStorageImages<'frozen, TriggerId, ()>,
    _active_time: FrozenStorageImages<'frozen, TriggerId, ()>,
    _active_by_call: FrozenStorageImages<'frozen, TriggerId, ()>,
    strategy: Option<CheckedStrategy>,
}
impl<'frozen> FrozenContracts<'frozen> {
    fn retain(block: &'frozen SetBlock<'_>, set: &Set) -> Option<Self> {
        if block.publication != AggregatePublication::Frozen {
            return None;
        }
        let fields = block.fields.as_ref()?;
        let data = fields.data_triggers.frozen_images()?;
        let pipeline = fields.pipeline_triggers.frozen_images()?;
        let time = fields.time_triggers.frozen_images()?;
        let by_call = fields.by_call_triggers.frozen_images()?;
        let contracts = fields.contracts.frozen_images()?;
        let ids = fields.ids.frozen_images()?;
        let active_data = fields.active_data_trigger_ids.frozen_images()?;
        let active_pipeline = fields.active_pipeline_trigger_ids.frozen_images()?;
        let active_time = fields.active_time_trigger_ids.frozen_images()?;
        let active_by_call = fields.active_by_call_trigger_ids.frozen_images()?;
        // Materialize every actual target and mode, with no foreign refresh/reacquisition.
        let targets = [
            data.belongs_to(&set.data_triggers),
            pipeline.belongs_to(&set.pipeline_triggers),
            time.belongs_to(&set.time_triggers),
            by_call.belongs_to(&set.by_call_triggers),
            contracts.belongs_to(&set.contracts),
            ids.belongs_to(&set.ids),
            active_data.belongs_to(&set.active_data_trigger_ids),
            active_pipeline.belongs_to(&set.active_pipeline_trigger_ids),
            active_time.belongs_to(&set.active_time_trigger_ids),
            active_by_call.belongs_to(&set.active_by_call_trigger_ids),
        ];
        let modes = [
            data.mode(),
            pipeline.mode(),
            time.mode(),
            by_call.mode(),
            contracts.mode(),
            ids.mode(),
            active_data.mode(),
            active_pipeline.mode(),
            active_time.mode(),
            active_by_call.mode(),
        ];
        if targets.iter().any(|owned| !owned) || modes.iter().any(|mode| *mode != modes[0]) {
            return None;
        }
        Some(Self {
            data,
            pipeline,
            time,
            by_call,
            contracts,
            _ids: ids,
            _active_data: active_data,
            _active_pipeline: active_pipeline,
            _active_time: active_time,
            _active_by_call: active_by_call,
            strategy: None,
        })
    }
    fn encode(
        &mut self,
        limits: LeafLimits,
        budget: &AllocationBudget,
        max_work: u64,
    ) -> Result<CanonicalTablePairedSnapshot, LeafError> {
        let sources = NativeSources {
            data: &self.data,
            pipeline: &self.pipeline,
            time: &self.time,
            by_call: &self.by_call,
            contracts: &self.contracts,
        };
        self.strategy = Some(CheckedStrategy::prepare(&sources, max_work, budget)?);
        let strategy = self
            .strategy
            .as_mut()
            .expect("prepared frozen original counter");
        strategy.validate(&sources)?;
        let rows = strategy.encoding_rows(&self.contracts)?;
        CanonicalTableLeafSet::paired_semantic_table_from_rows(
            "triggers.contracts",
            "iroha:state:trigger-contract-bytecode:v1",
            limits,
            budget,
            rows,
            BorrowedWorldContract::from,
        )
    }
}
impl SetBlock<'_> {
    /// Capture solely the actual ten-owner frozen context and five-source contract relation.
    pub(crate) fn capture_frozen_contracts_authority_table(
        &self,
        original: &Set,
        limits: LeafLimits,
        budget: &AllocationBudget,
        max_work: u64,
    ) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
        let Some(mut checked) = FrozenContracts::retain(self, original) else {
            return Ok(None);
        };
        let outcome = checked.encode(limits, budget, max_work);
        drop(checked);
        outcome.map(Some)
    }
}
#[cfg(test)]
#[path = "set_contract_capture/tests.rs"]
mod tests;
