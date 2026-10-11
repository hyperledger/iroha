//! Local committed-history authority for signer stream-token observations.

use super::{StreamTokenIssuerError, StreamTokenSignerPinsV1};
use super::{
    StreamTokenStateObserverClientV1,
    signer_completed_finality::{CompletedFinalityV1, PendingCompletedFinalityV1},
};
use iroha_core::state::{State, StateReadOnly, WorldReadOnly};
use iroha_core::{
    query::stream_token_custody::read_stream_token_custody_control_at_v1,
    sumeragi::certified_chain::{CertifiedChain, QcVerification},
};
use iroha_data_model::sorafs::capacity::ProviderId;
use mv::storage::StorageReadOnly;
use sorafs_manifest::signer::custody::SignerCustodyAnchorV1;
use sorafs_manifest::signer::stream_token::SignerStreamTokenReceiptV1;
use sorafs_manifest::signer::{
    custody_control::SignerCustodyControlStateV1,
    protocol::SignerPurposeBindingV1,
    stream_token_evidence::{
        SignerStreamTokenObservationPhaseV1, SignerStreamTokenStateObservationBodyV1,
        SignerStreamTokenStateSubjectV1,
    },
};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) struct FinalityFloorV1 {
    pub(super) height: u64,
    pub(super) block_hash: [u8; 32],
}

#[derive(Clone, Copy)]
pub(super) enum HistoricalFinalityV1 {
    Custody(SignerCustodyAnchorV1),
    Block(FinalityFloorV1),
}
impl HistoricalFinalityV1 {
    pub(super) fn coordinates(self) -> FinalityFloorV1 {
        match self {
            Self::Custody(anchor) => FinalityFloorV1 {
                height: anchor.height,
                block_hash: anchor.block_hash,
            },
            Self::Block(anchor) => anchor,
        }
    }
}

// This trait is private to the caller. Only tests may inject a simulated history; the public
// constructor always derives its implementation from the same Core State used by Torii.
pub(super) trait SignerFinalityV1: Send + Sync {
    fn require_completed_proof_source(&self) -> Result<(), StreamTokenIssuerError>;
    fn prepare_completed_check(
        &self,
        receipt: &SignerStreamTokenReceiptV1,
        phase: SignerStreamTokenObservationPhaseV1,
        observer: &dyn StreamTokenStateObserverClientV1,
    ) -> Result<PendingCompletedFinalityV1, StreamTokenIssuerError>;
    fn capture(
        &self,
        minimum: SignerCustodyAnchorV1,
    ) -> Result<FinalityFloorV1, StreamTokenIssuerError>;
    fn validate(
        &self,
        minimum: SignerCustodyAnchorV1,
        candidate: SignerCustodyAnchorV1,
        floor: FinalityFloorV1,
        historical: &[HistoricalFinalityV1],
        observation: &SignerStreamTokenStateObservationBodyV1,
        completed: Option<&CompletedFinalityV1>,
    ) -> Result<(), StreamTokenIssuerError>;
}

pub(super) struct CoreFinalityV1 {
    pub(super) state: Arc<State>,
    pub(super) pins: StreamTokenSignerPinsV1,
}
impl CoreFinalityV1 {
    pub(super) fn new(state: Arc<State>, pins: StreamTokenSignerPinsV1) -> Self {
        Self { state, pins }
    }
}
impl SignerFinalityV1 for CoreFinalityV1 {
    fn require_completed_proof_source(&self) -> Result<(), StreamTokenIssuerError> {
        let snapshot = iroha_core::query::stream_token_authority::observation::capture_stream_token_authority_v1(
            &self.state.view(), self.pins.binding(), [0; 32],
        ).map_err(|_| unavailable())?;
        check_control_pins(&snapshot.control, &self.pins)?;
        if snapshot.control.active_head.is_none()
            || snapshot.control.signer_revoked
            || snapshot.control.attester_revoked
        {
            return Err(unavailable());
        }
        Ok(())
    }
    fn prepare_completed_check(
        &self,
        receipt: &SignerStreamTokenReceiptV1,
        phase: SignerStreamTokenObservationPhaseV1,
        observer: &dyn StreamTokenStateObserverClientV1,
    ) -> Result<PendingCompletedFinalityV1, StreamTokenIssuerError> {
        self.prepare_native_completed_check(receipt, phase, observer)
    }
    fn capture(
        &self,
        minimum: SignerCustodyAnchorV1,
    ) -> Result<FinalityFloorV1, StreamTokenIssuerError> {
        let view = self.state.view();
        check_registered_provider(&view, &self.pins)?;
        let height = u64::try_from(view.block_hashes().len()).map_err(|_| unavailable())?;
        let block_hash = view
            .block_hashes()
            .last()
            .map(|hash| *hash.as_ref())
            .ok_or_else(unavailable)?;
        let current = read_stream_token_custody_control_at_v1(&view, self.pins.binding(), height)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let verified = VerifiedFinalityTargetsV1::verify(
            &view,
            &[
                HistoricalFinalityV1::Custody(minimum).coordinates(),
                FinalityFloorV1 { height, block_hash },
            ],
        )?;
        verified.check_anchor(&self.pins, minimum)?;
        check_control_pins(&current.state, &self.pins)?;
        if current.state.active_head.is_none()
            || current.state.signer_revoked
            || current.state.attester_revoked
        {
            return Err(unavailable());
        }
        Ok(FinalityFloorV1 { height, block_hash })
    }
    fn validate(
        &self,
        minimum: SignerCustodyAnchorV1,
        candidate: SignerCustodyAnchorV1,
        floor: FinalityFloorV1,
        historical: &[HistoricalFinalityV1],
        observation: &SignerStreamTokenStateObservationBodyV1,
        completed: Option<&CompletedFinalityV1>,
    ) -> Result<(), StreamTokenIssuerError> {
        if let Some(proof) = completed {
            proof.validate(observation)?;
        } else {
            reject_unproved_completion(observation)?;
        }
        let view = self.state.view();
        check_registered_provider(&view, &self.pins)?;
        if historical.is_empty()
            || historical.len() > 3
            || !matches!(historical[0], HistoricalFinalityV1::Custody(anchor)
                if anchor == observation.active_head.approved_anchor)
        {
            return Err(unavailable());
        }
        // One fresh view and one ascending certified walk authenticate every endpoint. Reopening
        // a reader for each endpoint would reverify the same prefix many times; retaining it
        // across calls would conceal changed durable evidence or current policy.
        let latest = u64::try_from(view.block_hashes().len()).map_err(|_| unavailable())?;
        // Startup only qualifies custody; it grants no operation or serving authority. A
        // separately certified descendant may preserve that exact custody while this signed
        // reply is in flight. Every live operation/admission phase still requires the exact tip.
        let startup_descendant = completed.is_none()
            && observation.phase == SignerStreamTokenObservationPhaseV1::Startup
            && matches!(
                observation.subject,
                SignerStreamTokenStateSubjectV1::CurrentCustody { .. }
            )
            && candidate.height < latest;
        let mut targets =
            Vec::with_capacity(3 + historical.len() + usize::from(startup_descendant));
        targets.extend([
            HistoricalFinalityV1::Custody(minimum).coordinates(),
            floor,
            HistoricalFinalityV1::Custody(candidate).coordinates(),
        ]);
        targets.extend(historical.iter().map(|anchor| anchor.coordinates()));
        if startup_descendant {
            targets.push(FinalityFloorV1 {
                height: latest,
                block_hash: view
                    .block_hashes()
                    .last()
                    .map(|hash| *hash.as_ref())
                    .ok_or_else(unavailable)?,
            });
        }
        let verified = VerifiedFinalityTargetsV1::verify(&view, &targets)?;
        verified.check_anchor(&self.pins, minimum)?;
        let current = verified.check_anchor(&self.pins, candidate)?;
        check_observed_control(&current, candidate, observation)?;
        for anchor in historical {
            if let HistoricalFinalityV1::Custody(anchor) = anchor {
                verified.check_anchor(&self.pins, *anchor)?;
            }
        }
        if startup_descendant {
            let latest_control =
                read_stream_token_custody_control_at_v1(&view, self.pins.binding(), latest)
                    .map_err(|_| unavailable())?
                    .ok_or_else(unavailable)?;
            let latest_state = verified.check_anchor(&self.pins, latest_control.anchor)?;
            // Compare the complete native control and its revision commitment, not just the
            // observed head. A renewal, policy/key change or revocation must still refuse.
            if latest_state != current
                || latest_control.anchor.state_digest != candidate.state_digest
            {
                return Err(unavailable());
            }
            check_observed_control(&latest_state, candidate, observation)?;
        }
        if candidate.height < floor.height
            || (candidate.height < latest && !startup_descendant)
            || candidate.height < minimum.height
            || (candidate.height == minimum.height && candidate != minimum)
        {
            return Err(unavailable());
        }
        Ok(())
    }
}
pub(super) fn reject_unproved_completion(
    observation: &SignerStreamTokenStateObservationBodyV1,
) -> Result<(), StreamTokenIssuerError> {
    // A signed observer's completed-row claim and a certified block alone cannot replace the
    // purpose-owned same-State Reserve/Complete and challenged Check proof.
    if matches!(
        observation.phase,
        SignerStreamTokenObservationPhaseV1::AfterCommit
            | SignerStreamTokenObservationPhaseV1::BeforeRelease
    ) || matches!(
        observation.subject,
        SignerStreamTokenStateSubjectV1::CompletedOperation { .. }
    ) {
        return Err(unavailable());
    }
    Ok(())
}
pub(super) fn check_registered_provider(
    view: &impl StateReadOnly,
    pins: &StreamTokenSignerPinsV1,
) -> Result<(), StreamTokenIssuerError> {
    let SignerPurposeBindingV1::StreamToken { provider_id } = pins.binding().purpose else {
        return Err(unavailable());
    };
    if view
        .world()
        .provider_owners()
        .get(&ProviderId::new(provider_id))
        .is_none()
    {
        return Err(unavailable());
    }
    Ok(())
}
/// Private, invocation-local evidence for a bounded set of targets from exactly one State view.
/// It has no wire form and cannot be retained by the lifecycle or reused with a different view.
struct VerifiedFinalityTargetsV1<'view, V: StateReadOnly> {
    view: &'view V,
    targets: Vec<FinalityFloorV1>,
}

impl<'view, V: StateReadOnly> VerifiedFinalityTargetsV1<'view, V> {
    fn verify(view: &'view V, targets: &[FinalityFloorV1]) -> Result<Self, StreamTokenIssuerError> {
        // Minimum, floor, candidate, optional startup tip and at most three historical endpoints.
        // Validate before allocating or iterating any caller-selected height range.
        if targets.is_empty()
            || targets.len() > 7
            || targets
                .iter()
                .any(|target| target.height == 0 || target.block_hash == [0; 32])
        {
            return Err(unavailable());
        }
        let mut targets = targets.to_vec();
        targets.sort_unstable_by_key(|target| target.height);
        let first = targets.first().ok_or_else(unavailable)?.height;
        let last = targets.last().ok_or_else(unavailable)?.height;
        // Genesis signatures authenticate the proposal, not its executed result. Always verify
        // its successor and the parent-result link, even if genesis is the only requested target.
        let through = if first == 1 { last.max(2) } else { last };
        if through > u64::try_from(view.block_hashes().len()).map_err(|_| unavailable())? {
            return Err(unavailable());
        }
        let reader = CertifiedChain::new(view).map_err(|_| unavailable())?;
        let mut matched = 0;
        for block in reader.walk(first, through) {
            let block = block.map_err(|_| unavailable())?;
            if block.height() > 1 && block.verification() != QcVerification::Verified {
                return Err(unavailable());
            }
            // Equal heights are not deduplicated: every independently supplied hash must match.
            while let Some(target) = targets.get(matched)
                && target.height == block.height()
            {
                if target.block_hash != *block.block_hash().as_ref() {
                    return Err(unavailable());
                }
                matched += 1;
            }
        }
        if matched != targets.len() {
            return Err(unavailable());
        }
        Ok(Self { view, targets })
    }

    fn check_anchor(
        &self,
        pins: &StreamTokenSignerPinsV1,
        anchor: SignerCustodyAnchorV1,
    ) -> Result<SignerCustodyControlStateV1, StreamTokenIssuerError> {
        if anchor.state_digest == [0; 32]
            || !self.targets.iter().any(|target| {
                target.height == anchor.height && target.block_hash == anchor.block_hash
            })
        {
            return Err(unavailable());
        }
        let native =
            read_stream_token_custody_control_at_v1(self.view, pins.binding(), anchor.height)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
        if native.anchor != anchor {
            return Err(unavailable());
        }
        check_control_pins(&native.state, pins)?;
        Ok(native.state)
    }
}
pub(super) fn check_control_pins(
    native: &SignerCustodyControlStateV1,
    pins: &StreamTokenSignerPinsV1,
) -> Result<(), StreamTokenIssuerError> {
    let trust = native.policy.custody_trust();
    let expected = pins.custody_trust();
    if &native.policy.binding != pins.binding()
        || trust.authority != expected.authority
        || trust.public_key != expected.public_key
        || trust.active_from_unix_ms != expected.active_from_unix_ms
        || trust.active_until_unix_ms != expected.active_until_unix_ms
        || trust.max_validity_ms != expected.max_validity_ms
        || trust.max_anchor_age_ms != expected.max_anchor_age_ms
    {
        return Err(unavailable());
    }
    Ok(())
}
pub(super) fn check_observed_control(
    native: &SignerCustodyControlStateV1,
    candidate: SignerCustodyAnchorV1,
    observation: &SignerStreamTokenStateObservationBodyV1,
) -> Result<(), StreamTokenIssuerError> {
    if observation.current_anchor != candidate
        || native.active_head != Some(observation.active_head)
        || native.signer_revoked != observation.signer_revoked
        || native.attester_revoked != observation.attester_revoked
        || native.signer_revoked
        || native.attester_revoked
    {
        return Err(unavailable());
    }
    Ok(())
}
const fn unavailable() -> StreamTokenIssuerError {
    StreamTokenIssuerError::SignerFinalityUnavailable
}

#[cfg(test)]
mod tests {
    use super::{FinalityFloorV1, VerifiedFinalityTargetsV1};
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };

    #[test]
    fn batched_finality_requires_certified_genesis_successor() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let genesis = FinalityFloorV1 {
            height: 1,
            block_hash: *chain.genesis().hash().as_ref(),
        };
        assert!(VerifiedFinalityTargetsV1::verify(&chain.state().view(), &[genesis]).is_err());
        chain.commit_at(2_000, Vec::new());
        VerifiedFinalityTargetsV1::verify(&chain.state().view(), &[genesis])
            .expect("the real successor certifies the genesis execution result");
    }

    #[test]
    fn batched_finality_bounds_targets_before_walking() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit_at(2_000, Vec::new());
        let view = chain.state().view();
        let valid = FinalityFloorV1 {
            height: 2,
            block_hash: *chain.committed(2).block_hash().as_ref(),
        };
        VerifiedFinalityTargetsV1::verify(&view, &[valid; 7])
            .expect("seven independently matched targets are allowed");
        let mut conflicting = valid;
        conflicting.block_hash[0] ^= 1;
        for invalid in [
            vec![valid, conflicting],
            vec![conflicting, valid],
            Vec::new(),
            vec![valid; 8],
            vec![FinalityFloorV1 { height: 0, ..valid }],
            vec![FinalityFloorV1 {
                height: u64::MAX,
                ..valid
            }],
            vec![FinalityFloorV1 {
                block_hash: [0; 32],
                ..valid
            }],
        ] {
            assert!(VerifiedFinalityTargetsV1::verify(&view, &invalid).is_err());
        }
    }
}
