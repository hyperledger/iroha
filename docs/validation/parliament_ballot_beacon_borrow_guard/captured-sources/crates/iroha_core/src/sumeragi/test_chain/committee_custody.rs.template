//! Explicit BLS test custody resolved only against authenticated scheduled committees.

use super::*;
use iroha_data_model::{
    nexus::ValidatorSeatReadinessContextV1,
    sumeragi::epoch::{ValidatorEpochContextV1, ValidatorGenerationV1},
};

impl CertifiedTestChain {
    /// Retain one candidate's actual BLS signing key without granting scheduling authority.
    /// Election, finalized DKG, beacon-share readiness and activation still require signed work.
    ///
    /// # Errors
    /// Rejects a non-BLS key or a peer whose local signing custody is already provisioned.
    pub fn provision_candidate_custody(&mut self, key: &KeyPair) -> Result<(), String> {
        let peer = PeerId::new(key.public_key().clone());
        let signer = KeyPairSigner::new(key).map_err(|error| error.to_string())?;
        if self.signer_for_member(&peer).is_some() {
            return Err("candidate peer already has original local custody".to_owned());
        }
        self.signers.push(signer);
        Ok(())
    }

    /// Borrow a provisioned BLS signer by identity, never by a stale genesis seat number.
    pub(super) fn signer_for_member(&self, peer: &PeerId) -> Option<&KeyPairSigner> {
        let key = super::super::crypto::core_key(peer.public_key()).ok()?;
        self.signers
            .iter()
            .find(|signer| signer.public_key() == &key)
    }

    /// Check the exact committed preparation and seat before a real beacon provider proves it.
    /// This returns no possession proof and grants no activation authority. The caller must
    /// separately use `prove_global_threshold_beacon_seat_readiness_v1` with the actual share.
    ///
    /// # Errors
    /// Rejects missing/rebound preparation, a foreign seat, or unavailable local BLS custody.
    pub fn check_prepared_seat_binding(
        &self,
        peer: &PeerId,
        generation: &ValidatorGenerationV1,
        context: &ValidatorSeatReadinessContextV1,
    ) -> Result<(), String> {
        let view = self.state.view();
        let transition = view
            .world()
            .validator_committee_transitions()
            .get(&context.target_epoch)
            .ok_or_else(|| "prepared seat has no authenticated original transition".to_owned())?;
        if transition.preparation.generation() != *generation
            || transition.readiness_context(context.validator_index)? != *context
            || generation.validators.get(context.validator_index as usize) != Some(peer)
            || self.signer_for_member(peer).is_none()
        {
            return Err("prepared seat differs from its authenticated original".to_owned());
        }
        Ok(())
    }

    /// Resolve historical and prospective certificates from independently authenticated State.
    pub(super) fn certificate_context(&self, height: u64) -> ValidatorEpochContextV1 {
        // An independently owned Worker can replay or publish this same original
        // State without advancing this fixture executor's local bookkeeping tip.
        // Resolve both historical seats and the sole successor from that actual
        // published parent, never from an invented context or stale seat index.
        let view = self.state.view();
        let parent_height =
            u64::try_from(view.height()).expect("bounded original published height");
        if height <= parent_height {
            super::committed_block(&view, height)
                .expect("a genuinely published fixture height")
                .commitment()
                .schedule
                .current
                .clone()
        } else {
            assert_eq!(
                height,
                parent_height + 1,
                "only the actual successor may be certified"
            );
            view.world()
                .consensus_schedule()
                .ready(height)
                .expect("the exact successor is authorized")
                .epoch
                .clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_custody_cannot_change_or_sign_the_original_authenticated_schedule() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let original = chain.certificate_context(2);
        let candidate = KeyPair::from_seed(vec![0xED; 32], Algorithm::BlsNormal);
        let peer = PeerId::new(candidate.public_key().clone());
        assert!(chain.signer_for_member(&peer).is_none());
        chain.provision_candidate_custody(&candidate).unwrap();
        assert!(chain.signer_for_member(&peer).is_some());
        assert_eq!(chain.height(), 1);
        assert!(
            !chain.crypto.is_admitted(
                &super::super::super::crypto::core_key(candidate.public_key()).unwrap()
            ),
            "provisioning alone cannot admit an unseated BLS key"
        );
        assert_eq!(chain.certificate_context(2), original);
        assert!(!original.committee.iter().any(|seat| seat.validator == peer));
        assert!(chain.provision_candidate_custody(&candidate).is_err());
        let wrong_algorithm = KeyPair::from_seed(vec![0xEE; 32], Algorithm::Ed25519);
        assert!(chain.provision_candidate_custody(&wrong_algorithm).is_err());
        chain.commit(Vec::new());
        assert_eq!(chain.committed(2).commitment().schedule.current, original);
        let (_, qc) = chain.committed_body(2).unwrap().unwrap();
        assert_eq!(qc.signers.count_ones(), 3);
    }

    #[test]
    fn unfrozen_seat_refuses_binding_without_granting_readiness() {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let original = chain.certificate_context(2);
        let generation = original.generation();
        let context = ValidatorSeatReadinessContextV1 {
            version: 1,
            network_id: generation.network_id,
            transition_id: [0x92; 32],
            target_epoch: 1,
            authority_generation: generation.generation,
            authority_id: generation.generation_id().unwrap(),
            first_height: 2,
            last_height: 10,
            validator_index: 0,
            beacon: iroha_data_model::sumeragi::epoch::InstalledBeaconEpochBindingV1 {
                session_id: [0x93; 32],
                transcript_hash: [0x94; 32],
            },
        };
        context.validate().unwrap();
        assert!(
            chain
                .check_prepared_seat_binding(&generation.validators[0], &generation, &context,)
                .is_err()
        );
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.certificate_context(2), original);
    }
}
