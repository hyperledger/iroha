//! Bounded operational Prepare/Commit voting for private settlement.
//!
//! The retained consensus key can sign only a phase body produced by the
//! committee verifier or by the read-only complete-barrier check. Prepare
//! returns only after the exact transition is durably staged. Commit requires
//! a locally durable Prepare QC and never writes world state.

use super::{
    committee::prepare_private_settlement_leg_v1,
    global_state::validate_private_settlement_prepare_lock_registration_v1,
    protocol::{
        sign_private_settlement_phase_vote_v1, validate_private_settlement_committee_authority_v1,
        validate_private_settlement_prepare_barrier_v1,
    },
    sidecar_store::PrivateSettlementFileSidecarStoreV1,
};
use crate::state::StateView;
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::nexus::{
    AtomicPrivateSettlementV1, PrivateSettlementPhaseBodyV1, PrivateSettlementPhaseCertificateV1,
    PrivateSettlementPhaseV1, PrivateSettlementPhaseVoteV1, PrivateSettlementPrepareBarrierV1,
};
use iroha_model_base::peer::PeerId;
use std::fmt;
use thiserror::Error;

/// Uniform redacted failure for operational participant-phase requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("private-settlement phase request rejected")]
pub struct PrivateSettlementPhaseErrorV1;

/// Runtime-only bounded signer for participant Prepare and Commit votes.
#[derive(Clone)]
pub struct PrivateSettlementPhaseSignerV1 {
    key_pair: KeyPair,
    peer_id: PeerId,
}

impl fmt::Debug for PrivateSettlementPhaseSignerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementPhaseSignerV1")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

impl PrivateSettlementPhaseSignerV1 {
    /// Retain one node-owned BLS-normal key behind the bounded capability.
    ///
    /// # Errors
    ///
    /// Rejects a non-BLS-normal key.
    pub fn new(key_pair: KeyPair) -> Result<Self, PrivateSettlementPhaseErrorV1> {
        if key_pair.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal) {
            return Err(PrivateSettlementPhaseErrorV1);
        }
        let peer_id = PeerId::from(key_pair.public_key().clone());
        Ok(Self { key_pair, peer_id })
    }

    /// Public identity of the retained node key.
    #[must_use]
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Independently verify the current WSV and fsync-stage before signing Prepare.
    ///
    /// # Errors
    ///
    /// Returns one redacted rejection for any request, WSV, proof, audit,
    /// availability, committee-membership, or persistence failure.
    pub fn prepare_vote(
        &self,
        state: &StateView<'_>,
        store: &PrivateSettlementFileSidecarStoreV1,
        manifest: &AtomicPrivateSettlementV1,
        payload_digest: Hash,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementPhaseVoteV1, PrivateSettlementPhaseErrorV1> {
        manifest
            .validate()
            .map_err(|_| PrivateSettlementPhaseErrorV1)?;
        let state_height =
            u64::try_from(state.height()).map_err(|_| PrivateSettlementPhaseErrorV1)?;
        if state_height != authoritative_height
            || manifest.network_id != state.network_id
            || authoritative_height < manifest.authority_context_height
            || authoritative_height > manifest.expiry_height
        {
            return Err(PrivateSettlementPhaseErrorV1);
        }
        let (_, authority) = store
            .validate_phase_manifest(
                payload_digest,
                &self.peer_id,
                manifest,
                authoritative_height,
            )
            .map_err(|_| PrivateSettlementPhaseErrorV1)?;
        validate_private_settlement_committee_authority_v1(
            state,
            manifest.authority_context_height,
            &authority,
        )
        .map_err(|_| PrivateSettlementPhaseErrorV1)?;
        let body = prepare_private_settlement_leg_v1(
            state,
            store,
            payload_digest,
            &self.peer_id,
            *state.network_id.as_bytes(),
            authoritative_height,
        )
        .map_err(|_| PrivateSettlementPhaseErrorV1)?;
        let manifest_digest = manifest
            .manifest_digest()
            .map_err(|_| PrivateSettlementPhaseErrorV1)?;
        if body.phase != PrivateSettlementPhaseV1::Prepare
            || body.bundle_id != manifest.bundle_id
            || body.manifest_digest != manifest_digest
        {
            return Err(PrivateSettlementPhaseErrorV1);
        }
        self.sign(body)
    }

    /// Verify the all-Prepare certified-body identity and local durable Prepare QC before Commit.
    ///
    /// This method only reads the restricted journal and cannot mutate the WSV.
    ///
    /// # Errors
    ///
    /// Returns one redacted rejection for incomplete, substituted, stale, or
    /// locally unprepared material.
    pub fn commit_vote(
        &self,
        state: &StateView<'_>,
        store: &PrivateSettlementFileSidecarStoreV1,
        payload_digest: Hash,
        barrier: &PrivateSettlementPrepareBarrierV1,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementPhaseVoteV1, PrivateSettlementPhaseErrorV1> {
        validate_private_settlement_prepare_barrier_v1(barrier)
            .map_err(|_| PrivateSettlementPhaseErrorV1)?;
        let state_height =
            u64::try_from(state.height()).map_err(|_| PrivateSettlementPhaseErrorV1)?;
        if state_height != authoritative_height || barrier.manifest.network_id != state.network_id {
            return Err(PrivateSettlementPhaseErrorV1);
        }
        validate_private_settlement_prepare_lock_registration_v1(
            &state.world.private_settlement_staged_locks,
            barrier,
            authoritative_height,
        )
        .map_err(|_| PrivateSettlementPhaseErrorV1)?;
        let body = store
            .commit_phase_body(payload_digest, &self.peer_id, barrier, authoritative_height)
            .map_err(|_| PrivateSettlementPhaseErrorV1)?;
        self.sign(body)
    }

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the complete phase body is transferred into the signed vote"
    )]
    fn sign(
        &self,
        body: PrivateSettlementPhaseBodyV1,
    ) -> Result<PrivateSettlementPhaseVoteV1, PrivateSettlementPhaseErrorV1> {
        sign_private_settlement_phase_vote_v1(body, &self.key_pair)
            .map_err(|_| PrivateSettlementPhaseErrorV1)
    }

    /// Verify and fsync one locally relevant aggregate phase certificate.
    ///
    /// Persisting the Prepare QC is a mandatory boundary before Commit signing.
    /// Persisting Commit evidence changes only the restricted journal and never WSV.
    ///
    /// # Errors
    ///
    /// Returns one redacted rejection for a substituted manifest, body, signer
    /// set, phase transition, or durable-store failure.
    pub fn persist_certificate(
        &self,
        store: &PrivateSettlementFileSidecarStoreV1,
        manifest: &AtomicPrivateSettlementV1,
        payload_digest: Hash,
        certificate: PrivateSettlementPhaseCertificateV1,
        authoritative_height: u64,
    ) -> Result<(), PrivateSettlementPhaseErrorV1> {
        store
            .validate_phase_manifest(
                payload_digest,
                &self.peer_id,
                manifest,
                authoritative_height,
            )
            .map_err(|_| PrivateSettlementPhaseErrorV1)?;
        match certificate.body.phase {
            PrivateSettlementPhaseV1::Prepare => {
                store.record_prepare_certificate(payload_digest, certificate, authoritative_height)
            }
            PrivateSettlementPhaseV1::Commit => {
                let prepared_bundle_digest = certificate.body.prepared_bundle_digest;
                store.record_commit_certificate(
                    payload_digest,
                    certificate,
                    prepared_bundle_digest,
                    authoritative_height,
                )
            }
        }
        .map_err(|_| PrivateSettlementPhaseErrorV1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_phase_signer_accepts_only_bls_and_redacts_key_material() {
        let non_bls = KeyPair::from_seed(vec![0x41; 32], Algorithm::Ed25519);
        assert!(matches!(
            PrivateSettlementPhaseSignerV1::new(non_bls),
            Err(PrivateSettlementPhaseErrorV1)
        ));

        let bls = KeyPair::from_seed(vec![0x42; 32], Algorithm::BlsNormal);
        let peer_id = PeerId::from(bls.public_key().clone());
        let signer = PrivateSettlementPhaseSignerV1::new(bls).expect("BLS signer");
        assert_eq!(signer.peer_id(), &peer_id);
        let debug = format!("{signer:?}");
        assert!(debug.contains("peer_id"));
        assert!(!debug.contains("private_key"));
    }
}
