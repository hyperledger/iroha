//! Reopen original disk custody for the independently executed reward component prefix.
//!
//! This fixture resource handoff is deliberately separate from snapshot admission.
//! It never accepts a caller-authored result, decoded World, or replacement certificate.

use super::*;
use std::num::NonZeroUsize;

impl CertifiedTestChain {
    /// Require every frame in this independently executed prefix to match disk exactly.
    pub(crate) fn validate_reward_crash_prefix(&self, source: &Kura) -> Result<(), String> {
        for height in 1..=self.height() {
            let height = NonZeroUsize::new(usize::try_from(height).map_err(|e| e.to_string())?)
                .ok_or_else(|| "reward crash prefix height is zero".to_owned())?;
            let original = self
                .kura
                .canonical_block_wire_bytes_for_testing(height)
                .map_err(|error| error.to_string())?;
            let recovered = source
                .canonical_block_wire_bytes_for_testing(height)
                .map_err(|error| error.to_string())?;
            if original != recovered {
                return Err("reward crash recovery has a different original prefix".to_owned());
            }
        }
        Ok(())
    }

    /// Continue the original durable suffix on its strictly reopened Kura and archive.
    ///
    /// The caller reconstructs the explicit component bootstrap first; matching
    /// prefix frames do not turn that bootstrap into a genesis-governed policy.
    /// Original committed-body admission and certified replay remain mandatory.
    pub(crate) fn replay_reward_crash_store(self, recovered: Arc<Kura>) -> Result<Self, String> {
        self.validate_reward_crash_prefix(&recovered)?;
        let root_scope = self.root_scope();
        let consensus_mode = self.validated_genesis.consensus_metadata().mode;
        let Self {
            state,
            kura,
            genesis,
            validated_genesis,
            genesis_account,
            executor,
            events: _,
            blocks,
            availability,
            signers,
            validators,
            npos_beacon_signers,
            crypto,
            instance,
            tip,
            clock,
            execution_clock,
            execution_time_source,
            lane_blocks,
        } = self;
        // Joining the old Worker retires every borrowed overlay before State's
        // local resource owner changes. No signal or cancellation is involved.
        drop(executor);
        drop(blocks);
        drop(availability);
        drop(kura);
        let mut state = Arc::try_unwrap(state)
            .map_err(|_| "reward crash fixture still has a borrowed State".to_owned())?;
        state.rebind_reward_crash_kura_for_testing(Arc::clone(&recovered))?;
        let state = Arc::new(state);
        let availability: Arc<dyn AvailabilitySchedule> = Arc::new(
            super::super::runtime_availability::NativeGlobalAvailability::new(
                Arc::clone(&state),
                instance,
                Arc::clone(&crypto),
            )
            .map_err(|error| error.to_string())?,
        );
        let staging = Staging::new();
        let shared: SharedCrypto = crypto.clone();
        let blocks = KuraBlockStore::new(
            Arc::clone(&recovered),
            shared,
            GENESIS_HEIGHT,
            root_scope,
            staging.clone(),
            state.ivm_execution_budget(),
            Arc::clone(&availability),
        );
        let (events, receiver) = tokio::sync::broadcast::channel(4096);
        let executor = StateExecutor::spawn(ExecutorContext {
            time_source: execution_time_source.clone(),
            state: Arc::clone(&state),
            native_context_archive: Arc::new(
                crate::query::native_context_archive::NativeContextArchive::open(
                    &recovered,
                    state.ivm_execution_budget(),
                    recovered.native_context_archive_max_bytes(),
                )
                .map_err(|error| error.to_string())?,
            ),
            queue: None,
            staging,
            events,
            genesis_account: genesis_account.clone(),
            consensus_mode: consensus_mode.into(),
            root_scope,
            applied: (tip.0, tip.1),
            crypto: Some(Arc::clone(&crypto)),
            applied_watch: Arc::new(crate::sumeragi::lanes::global::AppliedWatch::new(
                tip.0,
                state.view().latest_block_hash(),
            )),
            lane_blocks: Arc::clone(&lane_blocks),
        })
        .map_err(|error| error.to_string())?;
        let last = u64::try_from(recovered.blocks_count()).map_err(|error| error.to_string())?;
        let mut restored = Self {
            state,
            kura: recovered,
            genesis,
            validated_genesis,
            genesis_account,
            executor,
            events: receiver,
            blocks,
            availability,
            signers,
            validators,
            npos_beacon_signers,
            crypto,
            instance,
            tip,
            clock,
            execution_clock,
            execution_time_source,
            lane_blocks,
        };
        for height in restored.height() + 1..=last {
            let (body, qc) = restored
                .committed_body(height)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("durable original frame missing at {height}"))?;
            restored
                .executor
                .replay(&body, &qc)
                .map_err(|error| error.to_string())?;
            let committed = restored.committed(height);
            restored.tip = (height, committed.core_hash(), committed.result());
        }
        Ok(restored)
    }
}
