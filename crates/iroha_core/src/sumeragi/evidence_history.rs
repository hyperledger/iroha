//! Original native execution history supplies evidence authority.
//!
//! Signed report bytes carry no authority context. This reader authenticates the subject
//! configuration from its executed parent's successor slot, the parent's configuration from
//! its predecessor, and every demotion header through the original State tip. It never reads
//! the node-local CommitQC. The returned observation alone cannot publish monetary effects.
//!
//! Pending observation, canonical block admission, pristine finality effects and restored
//! evidence use this original-history verifier. TODO(S8 release blocker): retain all decoded
//! evidence/context allocations in the original preparation pool; source-read accounting alone
//! does not fund that graph. Native lane evidence retains its original source and branch owner;
//! completed offender vectors/compact keys move funded into admission. World record/COW
//! clones, decoded proofs and cryptographic context allocations remain unfunded TODOs.

use std::num::NonZeroUsize;

#[cfg(test)]
use iroha_data_model::block::consensus::EvidenceOffender;
use iroha_data_model::block::consensus::EvidenceScope;

mod funded_attribution;
use funded_attribution::{AttributionFields, FundedOffenders};
pub(crate) use funded_attribution::{FundedEvidenceAttribution, restore_attribution};
use iroha_data_model::query::error::QueryExecutionFail;
use iroha_sumeragi::{
    api::CommittedTip,
    evidence::{EvidenceContext, EvidenceError, verify_evidence},
    message::Evidence,
    topology::demotion_window,
    types::{EpochId, Hash32},
};

use super::{crypto::BlsCrypto, schedule::ScheduledSlot, startup::GENESIS_HEIGHT};
use crate::state::{NativeExecutionTip, StateReadOnly, WorldReadOnly};

/// Authentication failure keeps local source failures distinct from invalid signed reports.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeEvidenceError {
    /// Original history is missing, corrupt or refused by the supplied source budget.
    #[error("native evidence history: {0}")]
    History(crate::execution_attempt::ExecutionAttemptError<QueryExecutionFail>),
    /// Retained lane source I/O or local capacity refusal; never blame the signed report.
    #[error("native lane evidence source: {0}")]
    Source(crate::execution_attempt::ExecutionAttemptError<std::io::Error>),
    /// Exact local capacity/allocator refusal while retaining the offender graph.
    #[error(transparent)]
    Preparation(#[from] crate::state::EvidencePreparationError),
    /// The requested subject or its authenticated schedule is inconsistent.
    #[error("native evidence context: {0}")]
    Context(String),
    /// The exact original signed artifacts do not prove the reported offence.
    #[error("native evidence proof: {0}")]
    Proof(#[from] EvidenceError),
}

/// Original-history attribution. Private fields prevent decode from granting admission.
/// Finality application must bind the retained observation to its original State cut.
#[derive(Debug)]
pub(crate) struct VerifiedNativeEvidence {
    scope: EvidenceScope,
    tip: NativeExecutionTip,
    instance: Hash32,
    epoch: EpochId,
    authority_generation: Hash32,
    height: u64,
    offenders: FundedOffenders,
    safety_violation: bool,
}
impl VerifiedNativeEvidence {
    /// Original root or lane admission cut, authenticated independently of signed proof bytes.
    pub(crate) fn scope(&self) -> EvidenceScope {
        self.scope
    }
    /// Move verified signer owners into the canonical attribution without cloning them.
    pub(crate) fn into_attribution(self) -> FundedEvidenceAttribution {
        let Self {
            scope,
            tip: _,
            instance,
            epoch,
            authority_generation,
            height,
            offenders,
            safety_violation,
        } = self;
        offenders.into_attribution(AttributionFields {
            scope,
            instance: instance.0,
            height,
            epoch: epoch.epoch,
            context_id: epoch.context.0,
            authority_generation: authority_generation.0,
            safety_violation,
        })
    }
    /// Compare a restored claim with the full verified value without cloning its signer graph.
    pub(crate) fn matches_attribution(
        &self,
        claim: &iroha_data_model::block::consensus::EvidenceAttribution,
    ) -> bool {
        self.scope == claim.scope
            && self.instance.0 == claim.instance
            && self.height == claim.height
            && self.epoch.epoch == claim.epoch
            && self.epoch.context.0 == claim.context_id
            && self.authority_generation.0 == claim.authority_generation
            && self.offenders.as_slice() == claim.offenders
            && self.safety_violation == claim.safety_violation
    }
    /// Original execution cut from which all historical authority was authenticated.
    pub(crate) fn tip(&self) -> NativeExecutionTip {
        self.tip
    }
    /// Exact global instance, derived from signed genesis identity and configured chain.
    #[cfg(test)]
    pub(crate) fn instance(&self) -> Hash32 {
        self.instance
    }
    /// Scheduling epoch and complete context to which the signed offence belongs.
    #[cfg(test)]
    pub(crate) fn epoch(&self) -> EpochId {
        self.epoch
    }
    /// Original immutable signing generation, independent of scheduling epoch retention.
    #[cfg(test)]
    pub(crate) fn authority_generation(&self) -> Hash32 {
        self.authority_generation
    }
    /// Original subject height.
    #[cfg(test)]
    pub(crate) fn height(&self) -> u64 {
        self.height
    }
    /// Every directly accountable signer in authenticated historical committee order.
    #[cfg(test)]
    pub(crate) fn offenders(&self) -> &[EvidenceOffender] {
        self.offenders.as_slice()
    }
    /// Conflicting certified results demand a safety halt, even without attributable overlap.
    #[cfg(test)]
    pub(crate) fn safety_violation(&self) -> bool {
        self.safety_violation
    }
}

/// Claimed subject only; callers must authenticate it independently before using it.
pub(crate) fn subject(evidence: &Evidence) -> (Hash32, u64, u64) {
    match evidence {
        Evidence::ProposalEquivocation(first, _) => (first.instance, first.height, first.view),
        Evidence::VoteEquivocation(first, _) => (first.instance, first.height, first.view),
        Evidence::TimeoutEquivocation(first, _) => (first.instance, first.height, first.view),
        Evidence::InvalidProposal { proposal, .. } => {
            (proposal.instance, proposal.height, proposal.view)
        }
        Evidence::ConflictingCertificates(first, _) => (first.instance, first.height, first.view),
    }
}

fn position(height: u64) -> Result<NonZeroUsize, NativeEvidenceError> {
    usize::try_from(height)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| {
            NativeEvidenceError::Context("subject height is outside native history".into())
        })
}

/// Attribute a global-instance native report using one immutable original State history cut.
/// Every physical frame traversed from the tip is charged before reading, including frames
/// above the requested interval. A current-height observation may target tip+1; an admitting
/// block must separately enforce that the offence precedes its own height and the signed
/// evidence horizon. No World committee lookup or supplied HeightContext is accepted.
pub(crate) fn verify_from_state(
    state: &impl StateReadOnly,
    evidence: &Evidence,
    before_read: impl FnMut(
        u64,
        u64,
    ) -> Result<
        (),
        crate::execution_attempt::ExecutionAttemptError<QueryExecutionFail>,
    >,
) -> Result<VerifiedNativeEvidence, NativeEvidenceError> {
    let invalid = |reason: &str| NativeEvidenceError::Context(reason.into());
    let tip = state
        .native_execution_tip()
        .ok_or_else(|| invalid("original execution tip is absent"))?;
    let (claimed_instance, height, _) = subject(evidence);
    if height <= GENESIS_HEIGHT
        || height
            .checked_sub(1)
            .is_none_or(|parent| parent > tip.height())
    {
        return Err(invalid("subject has no original executed parent"));
    }
    let genesis_hash = state
        .block_hashes()
        .get(0)
        .ok_or_else(|| invalid("signed genesis identity is absent"))?;
    let crypto = BlsCrypto::new();
    // A genuine enclosing JSON refusal leaves original history authentication unfinished.
    // Missing or malformed metadata still supplies no root authority.
    let scope = if cfg!(all(test, sumeragi_core_mutation = "HC120")) {
        super::lanes::routing::committed_root_scope(state.world())
    } else {
        super::lanes::routing::read_routing_root_scope(state.world()).map_err(|reason| {
            NativeEvidenceError::History(crate::execution_attempt::ExecutionAttemptError::Deferred(
                reason,
            ))
        })?
    }
    .ok_or_else(|| invalid("signed immutable root scope is absent or malformed"))?;
    let instance = scope
        .instance_id(
            &crypto,
            iroha_data_model::NetworkId::from_genesis_hash(*genesis_hash),
            state.chain_id().as_str(),
        )
        .map_err(|error| invalid(&error.to_string()))?;
    if instance != claimed_instance {
        return Err(invalid(
            "report targets another network, chain or native instance",
        ));
    }
    let window = state.world().parameters().sumeragi().demotion_window.get();
    let interval = demotion_window(height, GENESIS_HEIGHT, window);
    let parent_height = height - 1;
    let grandparent_height = (parent_height > GENESIS_HEIGHT).then(|| parent_height - 1);
    let first = interval
        .map(|(first, _)| first)
        .unwrap_or(parent_height)
        .min(grandparent_height.unwrap_or(parent_height));
    let mut parent = None;
    let mut grandparent = None;
    let mut headers = Vec::new();
    state
        .canonical_history()
        .visit_executed_backwards(
            position(first)?,
            position(parent_height)?,
            before_read,
            |receipt| {
                let source_height = receipt.height();
                if interval
                    .is_some_and(|(first, last)| first <= source_height && source_height <= last)
                {
                    let header = receipt.header().ok_or_else(|| {
                        QueryExecutionFail::Conversion(
                            "native demotion interval contains no header".into(),
                        )
                    })?;
                    headers.push(header.clone());
                }
                if source_height == parent_height {
                    parent = Some(receipt);
                } else if Some(source_height) == grandparent_height {
                    grandparent = Some(receipt);
                }
                Ok(())
            },
        )
        .map_err(NativeEvidenceError::History)?;
    headers.reverse();
    let parent = parent.ok_or_else(|| invalid("original parent is absent"))?;
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        return Err(invalid("subject authority was not certified by its parent"));
    };
    if scheduled.height != height || scheduled.epoch.network_id != *state.network_id() {
        return Err(invalid(
            "subject schedule belongs to another height or network",
        ));
    }
    let config = scheduled
        .height_config()
        .map_err(|error| NativeEvidenceError::Context(error.to_string()))?;
    crypto
        .admit_committee(scheduled.epoch.committee.iter().map(|member| {
            (
                member.validator.public_key(),
                member.proof_of_possession.as_slice(),
            )
        }))
        .map_err(|(_, error)| NativeEvidenceError::Context(error.to_string()))?;
    let parent_config = match grandparent.as_ref() {
        None => None,
        Some(grandparent) => {
            let ScheduledSlot::Ready(scheduled) = &grandparent.commitment().schedule.next else {
                return Err(invalid(
                    "parent authority was not certified by its predecessor",
                ));
            };
            if scheduled.height != parent_height
                || scheduled.epoch.network_id != *state.network_id()
                || scheduled.epoch != parent.commitment().schedule.current
            {
                return Err(invalid(
                    "parent authority differs from its predecessor slot",
                ));
            }
            crypto
                .admit_committee(scheduled.epoch.committee.iter().map(|member| {
                    (
                        member.validator.public_key(),
                        member.proof_of_possession.as_slice(),
                    )
                }))
                .map_err(|(_, error)| NativeEvidenceError::Context(error.to_string()))?;
            Some(
                scheduled
                    .height_config()
                    .map_err(|error| NativeEvidenceError::Context(error.to_string()))?,
            )
        }
    };
    let parent_tip = CommittedTip {
        height: parent_height,
        block_hash: parent.core_hash(),
        result: parent.result(),
        header: parent.header().cloned(),
        commit_qc: None,
    };
    let context = EvidenceContext {
        instance,
        height,
        config: &config,
        genesis_height: GENESIS_HEIGHT,
        parent: &parent_tip,
        parent_config: parent_config.as_ref(),
        demotion_window: window,
        demotion_headers: &headers,
    };
    // Every native parent certificate requires an exact authenticated BLS quorum.
    // cannot authorize a proposal; independently signed conflicting values still prove safety.
    let attribution = verify_evidence(&crypto, &context, evidence)?;
    let budget = state.execution_budget();
    let offenders = FundedOffenders::collect(
        attribution.offenders().ones().count(),
        attribution.offenders().ones(),
        &budget,
        |signer, budget| {
            let member = scheduled
                .epoch
                .committee
                .get(signer as usize)
                .ok_or_else(|| {
                    invalid("verified signer is absent from its historical committee")
                })?;
            let source = member.validator.public_key();
            let layout = source.retained_allocation_layout();
            let charge = budget
                .try_reserve(layout)
                .map_err(crate::state::EvidencePreparationError::Admission)?
                .try_split(layout)
                .map_err(|_| crate::state::EvidencePreparationError::Invariant)?;
            let key =
                source
                    .try_clone_from_charge(budget, charge)
                    .map_err(|(_, error)| match error {
                        iroha_crypto::PublicKeyAllocationError::Allocation(
                            iroha_allocation::ChargedBufferFromChargeError::Allocator { layout },
                        ) => crate::state::EvidencePreparationError::Allocator {
                            requested_bytes: layout.size(),
                        },
                        _ => crate::state::EvidencePreparationError::Invariant,
                    })?;
            Ok((key, None))
        },
    )?;
    Ok(VerifiedNativeEvidence {
        scope: EvidenceScope::Root,
        tip,
        instance,
        epoch: config.epoch.id,
        authority_generation: config.epoch.authority_generation,
        height,
        offenders,
        safety_violation: attribution.safety_violation(),
    })
}

mod lane;
mod lane_read;
pub(crate) use lane_read::LaneEvidenceRead;

#[cfg(test)]
mod tests;
