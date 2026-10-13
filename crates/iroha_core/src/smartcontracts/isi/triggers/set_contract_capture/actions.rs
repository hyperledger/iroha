//! All ten actual Set sources retained through the shared inverse and canonical encoding.
//! Derived ID/active rows validate consistency; they grant no execution authority.
use super::super::action_relation::{ActionTable, NativeActions};
use super::super::contract_relation::Image;
use super::*;

/// Ten original publication owners; every source drops before the fixed counter owner.
pub(crate) struct CheckedActions<'set> {
    ids: CommittedStorageView<'set, TriggerId, TriggeringEventType>,
    active_data: CommittedStorageView<'set, TriggerId, ()>,
    active_pipeline: CommittedStorageView<'set, TriggerId, ()>,
    active_time: CommittedStorageView<'set, TriggerId, ()>,
    active_by_call: CommittedStorageView<'set, TriggerId, ()>,
    #[cfg(test)]
    probes: std::cell::Cell<[usize; 10]>,
    base: CheckedContracts<'set>,
}
macro_rules! sources {
    ($owner:expr) => {
        NativeSources {
            data: &$owner.data,
            pipeline: &$owner.pipeline,
            time: &$owner.time,
            by_call: &$owner.by_call,
            contracts: &$owner.contracts,
        }
    };
}
impl<'set> CheckedActions<'set> {
    /// Retain all original readers before validating either complete logical image.
    pub(crate) fn capture(
        set: &'set Set,
        max_work: u64,
        budget: &'set AllocationBudget,
    ) -> Result<Self, TriggerContractError> {
        let base = CheckedContracts::retain(set, budget)?;
        let mut checked = Self {
            ids: set.ids.try_committed_view_nonblocking()?,
            active_data: set
                .active_data_trigger_ids
                .try_committed_view_nonblocking()?,
            active_pipeline: set
                .active_pipeline_trigger_ids
                .try_committed_view_nonblocking()?,
            active_time: set
                .active_time_trigger_ids
                .try_committed_view_nonblocking()?,
            active_by_call: set
                .active_by_call_trigger_ids
                .try_committed_view_nonblocking()?,
            #[cfg(test)]
            probes: std::cell::Cell::new([0; 10]),
            base,
        };
        let result = (|| {
            let sources = sources!(checked.base);
            let inverse = NativeActions {
                data: &checked.base.data,
                pipeline: &checked.base.pipeline,
                time: &checked.base.time,
                by_call: &checked.base.by_call,
                ids: &checked.ids,
                active_data: &checked.active_data,
                active_pipeline: &checked.active_pipeline,
                active_time: &checked.active_time,
                active_by_call: &checked.active_by_call,
            };
            checked.base.strategy = Some(CheckedStrategy::prepare(&sources, max_work, budget)?);
            let work = checked
                .base
                .strategy
                .as_mut()
                .expect("prepared original action counter");
            work.validate_action_contract_image(&sources, Image::Current)?;
            inverse.validate(Image::Current, work)?;
            work.reset_action_contract_counts()?;
            work.validate_action_contract_image(&sources, Image::Predecessor)?;
            inverse.validate(Image::Predecessor, work)
        })();
        let current = checked.matches_current();
        if !current? {
            return Err(mv::PublicationPreparationError::Changed.into());
        }
        result?;
        Ok(checked)
    }
    /// Materialize all ten source identity Results before any refusal is propagated.
    pub(crate) fn matches_current(&self) -> Result<bool, TriggerContractError> {
        let set = self.base.set;
        let data = self.base.data.try_matches_current(&set.data_triggers);
        let pipeline = self
            .base
            .pipeline
            .try_matches_current(&set.pipeline_triggers);
        let time = self.base.time.try_matches_current(&set.time_triggers);
        let by_call = self.base.by_call.try_matches_current(&set.by_call_triggers);
        let ids = self.ids.try_matches_current(&set.ids);
        let active_data = self
            .active_data
            .try_matches_current(&set.active_data_trigger_ids);
        let active_pipeline = self
            .active_pipeline
            .try_matches_current(&set.active_pipeline_trigger_ids);
        let active_time = self
            .active_time
            .try_matches_current(&set.active_time_trigger_ids);
        let active_by_call = self
            .active_by_call
            .try_matches_current(&set.active_by_call_trigger_ids);
        let contracts = self.base.contracts.try_matches_current(&set.contracts);
        #[cfg(test)]
        self.probes.set(self.probes.get().map(|count| count + 1));
        let results = [
            data?,
            pipeline?,
            time?,
            by_call?,
            ids?,
            active_data?,
            active_pipeline?,
            active_time?,
            active_by_call?,
            contracts?,
        ];
        Ok(results.into_iter().all(|current| current))
    }
    /// Encode the same selected canonical action frame while every checked source lives.
    pub(crate) fn encode(
        &mut self,
        table: ActionTable,
        limits: LeafLimits,
    ) -> Result<CanonicalTablePairedSnapshot, LeafError> {
        let work = self
            .base
            .strategy
            .as_mut()
            .expect("checked original action counter");
        macro_rules! encode {
            ($field:ident,$table:literal,$domain:literal) => {{
                let rows = work.encoding_rows(&self.base.$field)?;
                CanonicalTableLeafSet::paired_semantic_table_from_rows(
                    $table,
                    $domain,
                    limits,
                    self.base.budget,
                    rows,
                    BorrowedWorldAction::new,
                )
            }};
        }
        match table {
            ActionTable::Data => {
                encode!(data, "triggers.data", "iroha:state:trigger-data-action:v1")
            }
            ActionTable::Pipeline => encode!(
                pipeline,
                "triggers.pipeline",
                "iroha:state:trigger-pipeline-action:v1"
            ),
            ActionTable::Time => {
                encode!(time, "triggers.time", "iroha:state:trigger-time-action:v1")
            }
            ActionTable::ByCall => encode!(
                by_call,
                "triggers.by_call",
                "iroha:state:trigger-by-call-action:v1"
            ),
        }
    }
}
impl FrozenContracts<'_> {
    fn encode_action(
        &mut self,
        table: ActionTable,
        limits: LeafLimits,
        budget: &AllocationBudget,
        max_work: u64,
    ) -> Result<CanonicalTablePairedSnapshot, LeafError> {
        let sources = sources!(self);
        let inverse = NativeActions {
            data: &self.data,
            pipeline: &self.pipeline,
            time: &self.time,
            by_call: &self.by_call,
            ids: &self.ids,
            active_data: &self.active_data,
            active_pipeline: &self.active_pipeline,
            active_time: &self.active_time,
            active_by_call: &self.active_by_call,
        };
        self.strategy = Some(CheckedStrategy::prepare(&sources, max_work, budget)?);
        let work = self
            .strategy
            .as_mut()
            .expect("prepared frozen original action counter");
        work.validate_action_contract_image(&sources, Image::Current)?;
        inverse.validate(Image::Current, work)?;
        work.reset_action_contract_counts()?;
        work.validate_action_contract_image(&sources, Image::Predecessor)?;
        inverse.validate(Image::Predecessor, work)?;
        macro_rules! encode {
            ($field:ident,$table:literal,$domain:literal) => {{
                let rows = work.encoding_rows(&self.$field)?;
                CanonicalTableLeafSet::paired_semantic_table_from_rows(
                    $table,
                    $domain,
                    limits,
                    budget,
                    rows,
                    BorrowedWorldAction::new,
                )
            }};
        }
        match table {
            ActionTable::Data => {
                encode!(data, "triggers.data", "iroha:state:trigger-data-action:v1")
            }
            ActionTable::Pipeline => encode!(
                pipeline,
                "triggers.pipeline",
                "iroha:state:trigger-pipeline-action:v1"
            ),
            ActionTable::Time => {
                encode!(time, "triggers.time", "iroha:state:trigger-time-action:v1")
            }
            ActionTable::ByCall => encode!(
                by_call,
                "triggers.by_call",
                "iroha:state:trigger-by-call-action:v1"
            ),
        }
    }
}
impl SetBlock<'_> {
    /// Validate both complete images from the same ten frozen targets and common mode.
    pub(crate) fn capture_frozen_action_authority_table(
        &self,
        original: &Set,
        table: ActionTable,
        limits: LeafLimits,
        budget: &AllocationBudget,
        max_work: u64,
    ) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
        let Some(mut checked) = FrozenContracts::retain(self, original) else {
            return Ok(None);
        };
        let outcome = checked.encode_action(table, limits, budget, max_work);
        drop(checked);
        outcome.map(Some)
    }
}
#[cfg(test)]
#[path = "actions/tests.rs"]
mod tests;
