//! Actual Network-derived events and bounded Pipeline invocation ownership.
//! Event positions and routing come from retained execution, never claimed outputs.

use super::internal::InternalInvocation;
use super::*;
use crate::smartcontracts::isi::triggers::set::{
    SetReadOnly, invocation_identity::pipeline_trigger_use_v1, pipeline_trigger_action_matches,
};
use iroha_data_model::{
    block::execution_output::{PipelineEventPositionV1, PipelineInvocationV1},
    events::{
        EventBox,
        pipeline::{
            BlockEvent, BlockStatus, PipelineEventBox, TransactionEvent, TransactionStatus,
        },
    },
    trigger::TriggerId,
};
use mv::storage::StorageReadOnly;

impl ExecutionOutputProducer<'_, '_, '_> {
    pub(super) fn execute_pipeline_outputs(&mut self) -> Result<(), ExecutionAttemptError<String>> {
        let result = (|| {
            if self.failed
                || self.pipeline_started
                || self.time_started
                || self.network_resolved.iter().any(|done| !done)
                || self.network_sources.is_none()
            {
                return Err("Pipeline phase requires one completed actual Network owner".into());
            }
            self.pipeline_started = true;
            self.skip_uninvoked(ExecutionOutputPhase::Pipeline, 0)?;
            let maximum = self.state.pipeline_trigger_candidate_limit()?;
            for index in 0..self.source.network_entrypoint_count() {
                let input = self
                    .source
                    .network_entrypoint_at(index)
                    .ok_or("Pipeline lost its exact Network source")?;
                let signed = match input {
                    TransactionEntrypoint::External(signed) => signed,
                    TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
                    TransactionEntrypoint::SealedCommitment(_)
                    | TransactionEntrypoint::AnonymousBallot(_) => {
                        self.skip_uninvoked(ExecutionOutputPhase::Pipeline, maximum)?;
                        continue;
                    }
                };
                let ExecutionOutputV1::Network(row) = &self.rows[index] else {
                    return Err("Pipeline event lost its Network result".into());
                };
                if usize::try_from(row.input_index).ok() != Some(index) {
                    return Err("Pipeline event changed its Network position".into());
                }
                let route = self
                    .network_route(index)
                    .ok_or("Pipeline event lacks frozen routing")?;
                // The retained canonical disposition is the event source. Keeping
                // a second unbounded rejection solely for this event is forbidden.
                let status = match row.result.as_ref() {
                    Ok(_) => TransactionStatus::Approved,
                    Err(reason) => TransactionStatus::Rejected(Box::new(reason.clone())),
                };
                let event = TransactionEvent {
                    hash: signed.hash(),
                    block_height: Some(self.source.header().height()),
                    lane_id: route.lane_id,
                    dataspace_id: route.dataspace_id,
                    status,
                };
                self.execute_pipeline_event(
                    PipelineEventPositionV1::Network(
                        u32::try_from(index).map_err(|_| "Pipeline source index exceeds u32")?,
                    ),
                    event.into(),
                    maximum,
                )?;
            }
            self.execute_pipeline_event(
                PipelineEventPositionV1::BlockApproved,
                BlockEvent {
                    header: self.source.header(),
                    status: BlockStatus::Approved,
                }
                .into(),
                maximum,
            )
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn execute_pipeline_event(
        &mut self,
        position: PipelineEventPositionV1,
        event: PipelineEventBox,
        maximum: u32,
    ) -> Result<(), ExecutionAttemptError<String>> {
        if self.state.gas_limit_per_block != 0
            && self.state.gas_used_in_block >= self.state.gas_limit_per_block
        {
            self.skip_uninvoked(ExecutionOutputPhase::Pipeline, maximum)?;
            return Ok(());
        }
        let height = self.source.header().height().get();
        let limit = usize::try_from(maximum).map_err(|_| "Pipeline capacity exceeds host width")?;
        let mut matched: Vec<TriggerId> = Vec::new();
        matched.try_reserve_exact(limit).map_err(|_| {
            ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            )
        })?;
        for id in self
            .state
            .world
            .triggers
            .match_pipeline_event(&event, height)
        {
            if matched.len() == limit {
                return Err("Pipeline matcher exceeded frozen capacity".into());
            }
            matched.push(id);
        }
        self.skip_uninvoked(
            ExecutionOutputPhase::Pipeline,
            maximum - u32::try_from(matched.len()).map_err(|_| "Pipeline count exceeds u32")?,
        )?;
        for (candidate_index, id) in matched.into_iter().enumerate() {
            if self.state.gas_limit_per_block != 0
                && self.state.gas_used_in_block >= self.state.gas_limit_per_block
            {
                self.skip_uninvoked(ExecutionOutputPhase::Pipeline, 1)?;
                continue;
            }
            let action = self
                .state
                .world
                .triggers
                .pipeline_triggers()
                .get(&id)
                .filter(|action| pipeline_trigger_action_matches(action, &event, height))
                .cloned();
            let Some(action) = action else {
                self.skip_uninvoked(ExecutionOutputPhase::Pipeline, 1)?;
                continue;
            };
            let invocation = PipelineInvocationV1 {
                event: position.clone(),
                candidate_index: u32::try_from(candidate_index)
                    .map_err(|_| "Pipeline index exceeds u32")?,
                trigger: pipeline_trigger_use_v1(&self.state.world.triggers, &id, height)?,
            };
            self.try_apply_internal(
                InternalInvocation::Pipeline(invocation),
                EventBox::Pipeline(event.clone()),
                &action,
            )?;
        }
        Ok(())
    }
}
