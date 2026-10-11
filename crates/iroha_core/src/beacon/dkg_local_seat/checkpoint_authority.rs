//! Checked DKG attempt and source authority, independent of raw crypto context DTOs.

use super::*;
use crate::{
    sumeragi::native_journal::NativeJournalCursor,
    validator_committee_evidence::VerifiedValidatorCommitteeSelectionV1,
};
use iroha_crypto::threshold_bls::{
    aggregate_checkpoint::DkgAggregateCheckpointBindingV1, checkpoint::DkgCheckpointSourceV1,
};
use iroha_data_model::{NetworkId, block::SignedBlock, parameter::system::ConsensusMode};
use iroha_model_base::chain::ChainId;

/// Exact frozen attempt derived from authenticated signed genesis or committee selection.
///
/// No public fields or raw-context constructor grant authority. The original proof
/// graph remains with the enclosing operation; restoration verifies it again before
/// this small checked owner exists. This authorizes DKG only, never activation.
pub struct AuthenticatedGlobalBeaconDkgAttemptV1 {
    session: GlobalThresholdBeaconDkgSessionV1,
    cutoff: u64,
    chain_hash: Hash,
    initial: DkgCheckpointSourceV1,
}
/// Complete checked phase source and frozen attempt binding for one private checkpoint.
/// This type cannot be constructed from caller supplied enum values or hashes.
pub struct VerifiedGlobalBeaconDkgCheckpointContextV1 {
    session: GlobalThresholdBeaconDkgSessionV1,
    binding: DkgCheckpointBindingV1,
}
/// Checked native-finalized aggregate source, separate from phase1..3 authorization.
///
/// Private fields prohibit promotion of raw crypto bindings into protocol
/// authority. A zero intent digest is permitted only while preparing immutable
/// intent bytes; private production/restore requires the actual nonzero hash.
pub struct VerifiedGlobalBeaconDkgAggregateContextV1 {
    session: GlobalThresholdBeaconDkgSessionV1,
    binding: DkgAggregateCheckpointBindingV1,
}
impl VerifiedGlobalBeaconDkgAggregateContextV1 {
    /// Borrow the complete original cryptographic context, not a new authorization.
    #[must_use]
    pub fn binding(&self) -> &DkgAggregateCheckpointBindingV1 {
        &self.binding
    }
    /// Original authenticated frozen session.
    #[must_use]
    pub fn session(&self) -> &GlobalThresholdBeaconDkgSessionV1 {
        &self.session
    }
    pub(super) fn matches_public(
        &self,
        public: &super::super::ValidatedGlobalThresholdBeaconSessionV1,
        lifecycle: &KeyPair,
    ) -> Result<(), LocalGlobalThresholdBeaconDkgErrorV1> {
        if public.record().adaptive_dkg.session != self.session
            || public.record().adaptive_dkg.finalized_at_height != self.binding.finalized_at_height
            || self.binding.public_session_hash
                != DkgAggregateCheckpointBindingV1::public_session_digest(public.record())
                    .map_err(DkgCheckpointErrorV1::from)?
            || self.binding.transcript_hash != *public.transcript().transcript_hash()
            || self.binding.extraction_intent_hash == [0; 32]
            || self.binding.lifecycle_key_hash
                != DkgCheckpointBindingV1::lifecycle_key_digest(lifecycle.public_key())
                    .map_err(DkgCheckpointErrorV1::from)?
            || public.record().adaptive_dkg.recipient_keys[usize::from(self.binding.seat_index - 1)]
                .validator
                .public_key()
                != lifecycle.public_key()
        {
            return Err(DkgCheckpointErrorV1::Binding.into());
        }
        Ok(())
    }
}

impl VerifiedGlobalBeaconDkgCheckpointContextV1 {
    /// Borrow canonical authenticated context; the DTO alone cannot grant authority.
    #[must_use]
    pub fn binding(&self) -> &DkgCheckpointBindingV1 {
        &self.binding
    }
    /// Exact original frozen session authenticated before this context was created.
    #[must_use]
    pub fn session(&self) -> GlobalThresholdBeaconDkgSessionV1 {
        self.session
    }
}
impl AuthenticatedGlobalBeaconDkgAttemptV1 {
    /// Authenticate signed H1 authorization, without attributing any execution result.
    ///
    /// The independently configured network must match the actual signed body.
    /// Signed native NPoS parameters own the cutoff and exact original roster.
    ///
    /// # Errors
    /// Rejects a foreign body, bad signature, malformed epoch, mode or closed windows.
    pub fn signed_genesis(
        genesis: &SignedBlock,
        network: NetworkId,
        chain_id: &ChainId,
    ) -> Result<Self, LocalGlobalThresholdBeaconDkgErrorV1> {
        let epoch = crate::sumeragi::epoch::authenticated_genesis(genesis)
            .map(|genesis| genesis.into_parts().0)
            .map_err(LocalGlobalThresholdBeaconDkgErrorV1::GenesisAuthority)?;
        if epoch.network_id != network
            || epoch.mode != ConsensusMode::Npos
            || epoch.authorization.first_height != 1
            || epoch.authorization.epoch != 0
            || epoch.authorization.authority_generation != 0
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        let cutoff = epoch
            .authorization
            .last_height
            .checked_sub(1)
            .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?;
        let committee_size = u16::try_from(epoch.committee.len())
            .map_err(|_| GlobalThresholdBeaconError::InvalidDkgSession)?;
        let roster_hash = super::super::global_threshold_beacon_roster_hash_v1(
            &epoch
                .committee
                .iter()
                .map(|seat| seat.validator.clone())
                .collect::<Vec<_>>(),
        );
        let session = GlobalThresholdBeaconDkgSessionV1 {
            version: 1,
            network_id: network,
            session_id: super::super::ceremony::global_beacon_genesis_session_id_v1(network),
            attempt_id: super::super::ceremony::global_beacon_genesis_attempt_id_v1(network),
            authority_generation: 0,
            roster_hash,
            committee_size,
            threshold: (committee_size - 1) / 3 + 1,
            start_height: 1,
            commitments_end_height: 2,
            deliveries_end_height: 3,
            acceptances_end_height: 4,
        };
        super::super::validate_dkg_session(&session)?;
        if session.acceptances_end_height >= cutoff {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        #[cfg(all(test, sumeragi_core_mutation = "HC108"))]
        let cutoff = cutoff.checked_add(1).expect("mutation cutoff fits");
        Ok(Self {
            session,
            cutoff,
            chain_hash: Hash::new(chain_id.as_str().as_bytes()),
            initial: DkgCheckpointSourceV1::SignedGenesisAuthorization {
                genesis_hash: *network.as_bytes(),
            },
        })
    }
    /// Bind the immutable selected target to its genuine native observed tip.
    ///
    /// # Errors
    /// Rejects another network, height, incumbent generation or insufficient frozen cutoff.
    pub fn rotation(
        selection: &VerifiedValidatorCommitteeSelectionV1,
        clock: &NativeJournalCursor,
    ) -> Result<Self, LocalGlobalThresholdBeaconDkgErrorV1> {
        let preparation = selection.preparation();
        let tip = clock
            .tip()
            .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?;
        if clock.network_id() != preparation.network_id
            || tip.height() != selection.observed_height()
            || tip.commitment().schedule.current.generation() != *selection.incumbent_authority()
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        let start = tip.height();
        let cutoff = preparation
            .first_height
            .checked_sub(1)
            .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?;
        let committee_size = u16::try_from(preparation.committee.len())
            .map_err(|_| GlobalThresholdBeaconError::InvalidDkgSession)?;
        let roster_hash = super::super::global_threshold_beacon_roster_hash_v1(
            &preparation
                .committee
                .iter()
                .map(|seat| seat.validator.clone())
                .collect::<Vec<_>>(),
        );
        let session = GlobalThresholdBeaconDkgSessionV1 {
            version: 1,
            network_id: preparation.network_id,
            session_id: preparation
                .beacon_session_id()
                .map_err(|_| GlobalThresholdBeaconError::InvalidDkgSession)?,
            attempt_id: preparation
                .transition_id()
                .map_err(|_| GlobalThresholdBeaconError::InvalidDkgSession)?,
            authority_generation: preparation.authority_generation,
            roster_hash,
            committee_size,
            threshold: (committee_size - 1) / 3 + 1,
            start_height: start,
            commitments_end_height: start
                .checked_add(1)
                .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?,
            deliveries_end_height: start
                .checked_add(2)
                .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?,
            acceptances_end_height: start
                .checked_add(3)
                .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?,
        };
        super::super::validate_dkg_session(&session)?;
        if session.acceptances_end_height >= cutoff {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        Ok(Self {
            session,
            cutoff,
            chain_hash: Hash::new(clock.chain_id().as_str().as_bytes()),
            initial: source_from_tip(tip),
        })
    }
    /// Derive only the actual finalized extraction source for this sealed original session.
    /// This context value grants no activation or signing authority.
    ///
    /// # Errors
    /// Rejects another source, frozen cutoff, session or incomplete finalization.
    pub fn finalized_source(
        &self,
        clock: &NativeJournalCursor,
        session: &super::super::ValidatedGlobalThresholdBeaconSessionV1,
    ) -> Result<DkgCheckpointSourceV1, LocalGlobalThresholdBeaconDkgErrorV1> {
        let tip = clock
            .tip()
            .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?;
        #[cfg(all(test, sumeragi_core_mutation = "HC114"))]
        let finalized_height_matches = true;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC114")))]
        let finalized_height_matches = tip.height() >= self.session.acceptances_end_height
            && session.record().adaptive_dkg.finalized_at_height == tip.height();
        if clock.network_id() != self.session.network_id
            || Hash::new(clock.chain_id().as_str().as_bytes()) != self.chain_hash
            || !finalized_height_matches
            || tip.height() >= self.cutoff
            || session.record().adaptive_dkg.session != self.session
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        Ok(source_from_tip(tip))
    }

    /// Derive the exact original aggregate context from the genuine finalized native tip.
    ///
    /// Accepted checkpoint/head and extraction intent hashes refer to original
    /// authenticated durable files; the daemon verifies that complete chain and
    /// frozen expiry before private production/adoption. A zero intent hash is
    /// allowed only to prepare the immutable intent, never to seal or restore.
    ///
    /// # Errors
    /// Refuses a foreign source/session/seat/lifecycle/provider, cutoff or prior head.
    pub fn aggregate_context(
        &self,
        clock: &NativeJournalCursor,
        public: &super::super::ValidatedGlobalThresholdBeaconSessionV1,
        seat: u16,
        lifecycle: &KeyPair,
        provider_handle: &str,
        provider_revision: u64,
        accepted_checkpoint_hash: [u8; 32],
        accepted_head_hash: [u8; 32],
        extraction_intent_hash: [u8; 32],
    ) -> Result<VerifiedGlobalBeaconDkgAggregateContextV1, LocalGlobalThresholdBeaconDkgErrorV1>
    {
        let source = self.finalized_source(clock, public)?;
        if seat == 0
            || seat > self.session.committee_size
            || lifecycle.public_key().algorithm() != iroha_crypto::Algorithm::BlsNormal
            || public.record().adaptive_dkg.recipient_keys[usize::from(seat - 1)]
                .validator
                .public_key()
                != lifecycle.public_key()
            || provider_revision == 0
            || iroha_config::parameters::validate_production_runtime_handle(provider_handle)
                .is_err()
            || accepted_checkpoint_hash == [0; 32]
            || accepted_head_hash == [0; 32]
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        let binding = DkgAggregateCheckpointBindingV1 {
            network_id: *self.session.network_id.as_bytes(),
            attempt_id: self.session.attempt_id,
            authority_generation: self.session.authority_generation,
            session_id: self.session.session_id,
            roster_hash: self.session.roster_hash,
            seat_index: seat,
            lifecycle_key_hash: DkgCheckpointBindingV1::lifecycle_key_digest(
                lifecycle.public_key(),
            )
            .map_err(DkgCheckpointErrorV1::from)?,
            provider_handle_hash: Hash::new(provider_handle.as_bytes()).into(),
            provider_revision,
            start_height: self.session.start_height,
            commitments_end_height: self.session.commitments_end_height,
            deliveries_end_height: self.session.deliveries_end_height,
            acceptances_end_height: self.session.acceptances_end_height,
            finalized_at_height: public.record().adaptive_dkg.finalized_at_height,
            source,
            cutoff_height: self.cutoff,
            public_session_hash: DkgAggregateCheckpointBindingV1::public_session_digest(
                public.record(),
            )
            .map_err(DkgCheckpointErrorV1::from)?,
            transcript_hash: *public.transcript().transcript_hash(),
            accepted_checkpoint_hash,
            accepted_head_hash,
            extraction_intent_hash,
        };
        Ok(VerifiedGlobalBeaconDkgAggregateContextV1 {
            session: self.session,
            binding,
        })
    }

    /// Original authenticated schedule; no caller-supplied replacement is accepted.
    #[must_use]
    pub fn session(&self) -> GlobalThresholdBeaconDkgSessionV1 {
        self.session
    }
    /// Original cutoff derived from signed protocol state, including finalization room.
    #[must_use]
    pub fn cutoff(&self) -> u64 {
        self.cutoff
    }
    /// Authenticate the original source and phase window before building its AEAD context.
    ///
    /// # Errors
    /// Rejects changed clocks, sources, lifecycle/provider identity, phase or frozen bounds.
    pub fn checkpoint_context(
        &self,
        clock: &NativeJournalCursor,
        phase: u16,
        seat: u16,
        lifecycle: &KeyPair,
        provider_handle: &str,
        provider_revision: u64,
        public_output_hash: [u8; 32],
        phase_input_hash: [u8; 32],
        previous_checkpoint_hash: [u8; 32],
        producer_intent_hash: [u8; 32],
    ) -> Result<VerifiedGlobalBeaconDkgCheckpointContextV1, LocalGlobalThresholdBeaconDkgErrorV1>
    {
        let foreign_clock = clock.network_id() != self.session.network_id
            || Hash::new(clock.chain_id().as_str().as_bytes()) != self.chain_hash;
        #[cfg(all(test, sumeragi_core_mutation = "HC104"))]
        let foreign_clock = false;
        if foreign_clock
            || !(1..=3).contains(&phase)
            || seat == 0
            || seat > self.session.committee_size
            || provider_revision == 0
            || iroha_config::parameters::validate_production_runtime_handle(provider_handle)
                .is_err()
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        let source = match (phase, clock.tip()) {
            (1, None)
                if matches!(
                    self.initial,
                    DkgCheckpointSourceV1::SignedGenesisAuthorization { .. }
                ) =>
            {
                self.initial
            }
            (_, Some(tip)) => source_from_tip(tip),
            _ => return Err(GlobalThresholdBeaconError::InvalidDkgSession.into()),
        };
        if phase == 1 && source != self.initial {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        let (first, end) = match phase {
            1 => (
                self.session.start_height,
                self.session.commitments_end_height,
            ),
            2 => (
                self.session.commitments_end_height,
                self.session.deliveries_end_height,
            ),
            _ => (
                self.session.deliveries_end_height,
                self.session.acceptances_end_height,
            ),
        };
        if source.height() < first || source.height() >= end || source.height() >= self.cutoff {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        let binding = DkgCheckpointBindingV1 {
            network_id: *self.session.network_id.as_bytes(),
            attempt_id: self.session.attempt_id,
            authority_generation: self.session.authority_generation,
            session_id: self.session.session_id,
            roster_hash: self.session.roster_hash,
            seat_index: seat,
            lifecycle_key_hash: DkgCheckpointBindingV1::lifecycle_key_digest(
                lifecycle.public_key(),
            )
            .map_err(DkgCheckpointErrorV1::from)?,
            provider_handle_hash: Hash::new(provider_handle.as_bytes()).into(),
            provider_revision,
            start_height: self.session.start_height,
            commitments_end_height: self.session.commitments_end_height,
            deliveries_end_height: self.session.deliveries_end_height,
            acceptances_end_height: self.session.acceptances_end_height,
            source,
            cutoff_height: self.cutoff,
            phase,
            public_output_hash,
            phase_input_hash,
            previous_checkpoint_hash,
            producer_intent_hash,
        };
        Ok(VerifiedGlobalBeaconDkgCheckpointContextV1 {
            session: self.session,
            binding,
        })
    }
}
fn source_from_tip(
    tip: &crate::sumeragi::certified_chain::CommittedBlock,
) -> DkgCheckpointSourceV1 {
    DkgCheckpointSourceV1::ExecutedNativeTip {
        height: tip.height(),
        block_hash: (*tip.block_hash()).into(),
        core_hash: tip.core_hash().0,
        result_hash: tip.result().0,
    }
}

#[cfg(test)]
mod tests;
