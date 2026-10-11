//! One serialized native producer, driven by every validator at its applied parent.
//!
//! A height has at most one reducer, one retransmitted own partial and one unique finalized
//! pulse. View changes and empty payload fallback never reset the pulse. Followers do not read
//! this owner: they decode the exact signed header witness and validate it in pristine State.
//!
//! TODO: the lower beacon session/transcript and cryptographic scratch still own
//! ordinary allocations. The reducer payload, partial slots and selected subset are
//! bounded inline; complete the remaining original-pool admission before qualification.

mod readiness;
pub(crate) use readiness::{NativeBeaconReadiness, NativeBeaconReadinessError};

use super::control;
use crate::{
    beacon::{
        GlobalThresholdBeaconError, GlobalThresholdBeaconPartialSignerV1,
        GlobalThresholdBeaconPulseAggregatorV1, GlobalThresholdBeaconSessionBindingV1,
        authenticated_global_threshold_beacon_roster_hash_iter_v1,
    },
    state::{NativeExecutionTip, StateReadOnly, WorldReadOnly},
    sumeragi::schedule,
};
use iroha_data_model::sumeragi::epoch::{BeaconEpochBindingV1, InstalledBeaconEpochBindingV1};
use iroha_data_model::{
    consensus::{
        FinalizedGlobalThresholdBeaconPulseV1 as Pulse, GlobalThresholdBeaconChainAnchorV1,
        GlobalThresholdBeaconPulseContextV1,
    },
    parameter::system::ConsensusMode,
    sumeragi::epoch::ValidatorEpochContextV1,
};
use iroha_sumeragi::{
    api::{ApplicationControlContext, ControlWitnessContext},
    message::ApplicationControl,
    types::{ControlWitness, Hash32, PublicKey},
};
use mv::storage::StorageReadOnly;
use std::sync::Arc;

/// Producer failure. AwaitingShares and source/local signer failures are local availability,
/// never an invalid transaction, fabricated empty witness or author-punishment signal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeBeaconError {
    /// The local applied source has not reached the exact requested context.
    #[error("native beacon source is unavailable or inconsistent: {0}")]
    Source(String),
    /// A required exact pulse is still waiting for actual valid threshold shares.
    #[error("native beacon at height {height} is waiting for authenticated shares")]
    AwaitingShares { height: u64 },
    /// The custody provider could not produce the exact local share on this attempt.
    #[error("native beacon local share custody is unavailable")]
    LocalSigning,
    /// The authenticated sender does not own the claimed exact DKG seat.
    #[error("native beacon sender differs from its exact DKG seat")]
    Sender,
    /// This sideframe belongs to another instance, epoch, height or applied parent.
    #[error("native beacon application control differs from the current original source")]
    Context,
    /// The actual transcript or proof did not validate.
    #[error(transparent)]
    Beacon(#[from] GlobalThresholdBeaconError),
    /// The finite canonical frame failed validation.
    #[error(transparent)]
    Codec(#[from] control::ControlCodecError),
}

/// Caller action for a typed producer refusal, without inspecting diagnostic strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeControlFailure {
    /// Local source advancement, custody or actual shares can resolve this refusal.
    Retryable,
    /// Discard the remote sideframe without poisoning the retained local round.
    Rejected,
    /// The applied State source or an internal checked invariant requires recovery.
    RecoveryRequired,
}
impl NativeBeaconError {
    /// Classification for this node's drive/build requests; no user transaction is accused.
    pub(crate) fn local_classification(&self) -> NativeControlFailure {
        match self {
            Self::Source(_) | Self::Codec(_) | Self::Beacon(_) => {
                NativeControlFailure::RecoveryRequired
            }
            Self::AwaitingShares { .. } | Self::LocalSigning | Self::Sender | Self::Context => {
                NativeControlFailure::Retryable
            }
        }
    }
    /// Classification after authenticated peer ingress; bad remote data is simply rejected.
    pub(crate) fn ingress_classification(&self) -> NativeControlFailure {
        match self {
            Self::Source(_) => NativeControlFailure::RecoveryRequired,
            Self::AwaitingShares { .. } | Self::LocalSigning => NativeControlFailure::Retryable,
            Self::Sender | Self::Context | Self::Beacon(_) | Self::Codec(_) => {
                NativeControlFailure::Rejected
            }
        }
    }
}

/// Result of one authenticated sideframe; duplicate valid proofs do not add another seat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IngressOutcome {
    Accepted,
    Duplicate,
    Finalized,
}

struct ActiveRound {
    aggregator: GlobalThresholdBeaconPulseAggregatorV1,
    roster: [[u8; 48]; 31],
    seats: usize,
    local: Option<u16>,
    own: Option<ControlWitness>,
    finalized: Option<Pulse>,
}

/// Process-lifetime owner retained by the sole StateExecutor Worker. Its signer is runtime
/// custody, never exported into World, configuration, canonical control bytes or diagnostics.
pub(crate) struct NativeBeaconProducer {
    instance: Hash32,
    local_bls: Option<[u8; 48]>,
    signer: Option<Arc<dyn GlobalThresholdBeaconPartialSignerV1>>,
    prepared: Option<ApplicationControlContext>,
    active: Option<ActiveRound>,
    readiness: Option<NativeBeaconReadiness>,
}
impl NativeBeaconProducer {
    /// Attach the actual native instance and optional runtime share custodian exactly once.
    pub(crate) fn new(
        instance: Hash32,
        local_bls: Option<[u8; 48]>,
        signer: Option<Arc<dyn GlobalThresholdBeaconPartialSignerV1>>,
    ) -> Self {
        Self {
            instance,
            local_bls,
            signer,
            prepared: None,
            active: None,
            readiness: None,
        }
    }

    /// Every validator calls this at applied-parent advancement and bounded retry ticks.
    /// The returned exact same own share is broadcast to the current committee on every call;
    /// no unbounded fanout queue is retained. The driver owns recoverable per-peer egress.
    pub(crate) fn drive(
        &mut self,
        state: &impl StateReadOnly,
        context: &ApplicationControlContext,
        applied: (u64, Hash32),
    ) -> Result<Option<ControlWitness>, NativeBeaconError> {
        self.ensure_source(state, context, applied)?;
        let Some(active) = self.active.as_mut() else {
            return Ok(None);
        };
        if active.own.is_none() {
            if let (Some(index), Some(signer)) = (active.local, self.signer.as_ref()) {
                signer
                    .attest_partial_signing_capability(active.aggregator.session(), index)
                    .map_err(|_| NativeBeaconError::LocalSigning)?;
                let partial = signer
                    .sign_partial(active.aggregator.session(), active.aggregator.payload())
                    .map_err(|_| NativeBeaconError::LocalSigning)?;
                if partial.signer_index != index {
                    return Err(NativeBeaconError::Sender);
                }
                // Encode before mutation; an encoding refusal cannot strand an admitted own
                // share without its exact retransmission bytes.
                let encoded = control::encode_partial(&partial)?;
                active
                    .aggregator
                    .accept_partial(partial)
                    .map_err(|_| NativeBeaconError::LocalSigning)?;
                active.own = Some(encoded);
                active.finish()?;
            }
        }
        Ok(active.own)
    }

    /// Admit an authenticated peer's bounded native sideframe. The same committed source is
    /// checked independently before touching the reducer, including ingress before first tick.
    pub(crate) fn accept(
        &mut self,
        state: &impl StateReadOnly,
        applied: (u64, Hash32),
        sender: &PublicKey,
        message: &ApplicationControl,
    ) -> Result<IngressOutcome, NativeBeaconError> {
        self.ensure_source(state, &message.context, applied)?;
        let active = self.active.as_mut().ok_or(NativeBeaconError::Context)?;
        let partial = control::decode_partial(&message.bytes)?;
        let index = usize::from(partial.signer_index)
            .checked_sub(1)
            .filter(|index| *index < active.seats)
            .ok_or(NativeBeaconError::Sender)?;
        if sender.as_bytes() != active.roster[index].as_slice() {
            return Err(NativeBeaconError::Sender);
        }
        let inserted = active.aggregator.accept_partial(partial)?;
        let was_finalized = active.finalized.is_some();
        active.finish()?;
        Ok(if !was_finalized && active.finalized.is_some() {
            IngressOutcome::Finalized
        } else if inserted {
            IngressOutcome::Accepted
        } else {
            IngressOutcome::Duplicate
        })
    }

    /// Build only for an already checked exact source. No-demand is explicit, while demanded
    /// missing work returns AwaitingShares even for EMPTY or a later view.
    pub(crate) fn build(
        &self,
        context: &ControlWitnessContext,
    ) -> Result<ControlWitness, NativeBeaconError> {
        let source = ApplicationControlContext {
            instance: self.instance,
            epoch: context.epoch,
            height: context.height,
            parent_hash: context.parent_hash,
            parent_result: context.parent_result,
        };
        if self.prepared.as_ref() != Some(&source) {
            return Err(NativeBeaconError::Context);
        }
        let pulse = match &self.active {
            None => None,
            Some(active) => Some(active.finalized.ok_or(NativeBeaconError::AwaitingShares {
                height: context.height,
            })?),
        };
        control::encode(pulse).map_err(NativeBeaconError::from)
    }

    /// Bind only the current parent to the opaque authority retained by this State
    /// publication. The original worker (or authenticated replay) issued this tip;
    /// local frame decoding grants no additional authority for these fixed fields.
    fn parent_source(
        &self,
        state: &impl StateReadOnly,
        context: &ApplicationControlContext,
        applied: (u64, Hash32),
    ) -> Result<NativeExecutionTip, NativeBeaconError> {
        if context.instance != self.instance
            || applied.0.checked_add(1) != Some(context.height)
            || applied.1 != context.parent_hash
            || u64::try_from(state.height()).ok() != Some(applied.0)
        {
            return Err(NativeBeaconError::Context);
        }
        let parent = state.native_execution_tip().ok_or_else(|| {
            NativeBeaconError::Source("published State has no original execution tip".into())
        })?;
        let journal_matches = {
            #[cfg(all(test, sumeragi_core_mutation = "HC17"))]
            {
                true
            }
            #[cfg(not(all(test, sumeragi_core_mutation = "HC17")))]
            {
                state.block_hashes().last() == Some(&parent.iroha_hash())
            }
        };
        if parent.height() != applied.0 || !journal_matches {
            return Err(NativeBeaconError::Source(
                "original execution tip differs from the published State hash journal".into(),
            ));
        }
        if parent.core_hash() != context.parent_hash || parent.result() != context.parent_result {
            return Err(NativeBeaconError::Context);
        }
        Ok(parent)
    }

    fn ensure_source(
        &mut self,
        state: &impl StateReadOnly,
        context: &ApplicationControlContext,
        applied: (u64, Hash32),
    ) -> Result<(), NativeBeaconError> {
        let parent = self.parent_source(state, context, applied)?;
        let retained = state.world().consensus_schedule();
        let scheduled = retained
            .ready(context.height)
            .map_err(|error| NativeBeaconError::Source(error.to_string()))?;
        let current = &scheduled.epoch;
        if current.network_id != *state.network_id()
            || schedule::core_epoch(current)
                .map_err(|error| NativeBeaconError::Source(error.to_string()))?
                .id
                != context.epoch
        {
            return Err(NativeBeaconError::Context);
        }
        let root_scope = crate::sumeragi::lanes::routing::committed_root_scope(state.world())
            .ok_or_else(|| {
                NativeBeaconError::Source("native control requires immutable root scope".into())
            })?;
        let required = super::required(root_scope, state.world(), current, context.height)
            .map_err(NativeBeaconError::Source)?;
        if self.prepared.as_ref() == Some(context) {
            return Ok(());
        }
        let active = if required {
            super::validate_pending_slot(state.world(), current, context.height)
                .map_err(NativeBeaconError::Source)?;
            Some(ActiveRound::open(
                state.world(),
                current,
                context.height,
                GlobalThresholdBeaconChainAnchorV1 {
                    height: applied.0,
                    block_hash: parent.iroha_hash(),
                },
                self.local_bls,
                pulse_context(context),
            )?)
        } else {
            None
        };
        self.active = active;
        self.prepared = Some(*context);
        Ok(())
    }
}

/// Fixed-width projection used only after independently checking the native source above.
fn pulse_context(context: &ApplicationControlContext) -> GlobalThresholdBeaconPulseContextV1 {
    GlobalThresholdBeaconPulseContextV1 {
        instance: context.instance.0,
        epoch: context.epoch.epoch,
        epoch_context_id: context.epoch.context.0,
        parent_consensus_hash: context.parent_hash.0,
        parent_result: context.parent_result.0,
    }
}

impl ActiveRound {
    fn open(
        world: &impl WorldReadOnly,
        current: &ValidatorEpochContextV1,
        height: u64,
        anchor: GlobalThresholdBeaconChainAnchorV1,
        local_bls: Option<[u8; 48]>,
        context: GlobalThresholdBeaconPulseContextV1,
    ) -> Result<Self, NativeBeaconError> {
        current.validate().map_err(NativeBeaconError::Source)?;
        let id = world
            .active_global_beacon_key_session()
            .ok_or_else(|| NativeBeaconError::Source("active session is absent".into()))?;
        let record = world
            .global_beacon_key_sessions()
            .get(&id)
            .ok_or_else(|| NativeBeaconError::Source("active session record is absent".into()))?;
        record
            .validate()
            .map_err(|error| NativeBeaconError::Source(error.to_string()))?;
        let binding = InstalledBeaconEpochBindingV1 {
            session_id: id,
            transcript_hash: record.session.transcript_hash,
        };
        if !record.is_active_at(height)
            || record.session.adaptive_dkg.finalized_at_height > anchor.height
            || record.session.network_id != current.network_id
            || record.session.adaptive_dkg.session.authority_generation
                != current.authorization.authority_generation
            || (current.authorization.beacon != BeaconEpochBindingV1::Bootstrap
                && current.authorization.beacon != BeaconEpochBindingV1::Installed(binding))
        {
            return Err(NativeBeaconError::Source(
                "active session differs from the authenticated epoch or finalized parent".into(),
            ));
        }
        let peers = current.committee.iter().map(|seat| &seat.validator);
        let roster_hash =
            authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session, peers)
                .map_err(|error| NativeBeaconError::Source(error.to_string()))?;
        let session = record.session.clone();
        session
            .check_binding(&GlobalThresholdBeaconSessionBindingV1 {
                network_id: current.network_id,
                session_id: id,
                roster_hash,
                transcript_hash: record.session.transcript_hash,
            })
            .map_err(|error| NativeBeaconError::Source(error.to_string()))?;
        let mut roster = [[0; 48]; 31];
        let mut local = None;
        for (index, seat) in current.committee.iter().enumerate() {
            let (algorithm, bytes) = seat
                .validator
                .public_key()
                .try_to_bytes()
                .map_err(|_| NativeBeaconError::Context)?;
            if algorithm != iroha_crypto::Algorithm::BlsNormal || bytes.len() != 48 {
                return Err(NativeBeaconError::Context);
            }
            roster[index].copy_from_slice(bytes);
            if Some(roster[index]) == local_bls {
                local = Some(u16::try_from(index + 1).map_err(|_| NativeBeaconError::Context)?);
            }
        }
        Ok(Self {
            aggregator: GlobalThresholdBeaconPulseAggregatorV1::new(
                session, height, anchor, context,
            )
            .map_err(|error| NativeBeaconError::Source(error.to_string()))?,
            roster,
            seats: current.committee.len(),
            local,
            own: None,
            finalized: None,
        })
    }
    fn finish(&mut self) -> Result<(), NativeBeaconError> {
        if self.finalized.is_none()
            && self.aggregator.verified_partial_count()
                >= usize::from(self.aggregator.session().record().threshold)
        {
            self.finalized = Some(
                self.aggregator
                    .finalize()
                    .map_err(|error| NativeBeaconError::Source(error.to_string()))?,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
