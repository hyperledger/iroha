//! Canonical global threshold-beacon verification.
//!
//! A first-release pulse is one unique threshold-BLS group signature over an
//! exact network, key session, slot, transcript, and finalized
//! chain anchor. Its public seed is derived only after final-signature
//! verification. Reconstruction shares and signer subsets are deliberately not
//! part of the pulse DTO, so different qualifying subsets cannot create
//! different public representations of the same pulse.
//!
//! The first-release module exposes only this threshold-beacon construction;
//! retired per-validator VRF constructions are deliberately absent.

/// Signed all-edge DKG ceremony, seat credentials and install certificates.
pub mod ceremony;
/// Runtime credential codec for global-beacon seat shares.
pub mod credential;
/// Proof-bearing custody of every exact prepared target seat.
pub mod seat_readiness;

mod dkg_local_seat;
mod session_owner;
use session_owner::{DkgMessageWorkspace, DkgRows};
pub use session_owner::{
    GlobalThresholdBeaconInputDestinationErrorV1, GlobalThresholdBeaconInputErrorV1,
    PreparedGlobalThresholdBeaconDkgInputsV1, PreparedGlobalThresholdBeaconDkgPublicationV1,
    PreparedGlobalThresholdBeaconFinalSessionInputV1,
    RetainedGlobalThresholdBeaconDkgFinalizationV1, RetainedGlobalThresholdBeaconDkgSnapshotV1,
};
mod validation;
pub use dkg_local_seat::{
    AuthenticatedGlobalBeaconDkgAttemptV1, GlobalBeaconAggregateOwnerV1,
    LocalGlobalThresholdBeaconDkgErrorV1, LocalGlobalThresholdBeaconDkgSeatV1,
    PreparedGlobalBeaconAggregateRestoreV1, PreparedLocalGlobalThresholdBeaconDkgSeatV1,
    VerifiedGlobalBeaconDkgAggregateContextV1, VerifiedGlobalBeaconDkgCheckpointContextV1,
};

#[cfg(any(test, feature = "iroha-core-tests"))]
pub use seat_readiness::prove_global_threshold_beacon_seat_readiness_v1;
pub use seat_readiness::{
    global_threshold_beacon_seat_readiness_challenge_v1,
    verify_global_threshold_beacon_seat_readiness_v1,
};

use iroha_crypto::{
    Algorithm, Hash,
    threshold_bls::{
        AdaptiveThresholdBlsParameters, AdaptiveThresholdBlsPublicTranscript,
        AdaptiveThresholdBlsSecretShare, BeaconPurpose, DasRenDealerCommitment,
        DasRenPartialSignature, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1, ThresholdBlsError,
        ThresholdBlsPublicKey, ThresholdBlsSession, ThresholdBlsSignature,
        ValidatedDealerCommitment,
    },
};
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_crypto::{HashOf, threshold_bls::DasRenDealerSecret};
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_data_model::block::BlockHeader;
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_data_model::consensus::GlobalThresholdBeaconDkgConstantProofV1;
use iroha_data_model::{
    NetworkId,
    consensus::{
        FinalizedGlobalThresholdBeaconPulseV1, GLOBAL_THRESHOLD_BEACON_VERSION_V1,
        GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconDkgDealerCommitmentV1,
        GlobalThresholdBeaconDkgEncryptedShareV1, GlobalThresholdBeaconDkgRecipientKeyV1,
        GlobalThresholdBeaconDkgSessionV1, GlobalThresholdBeaconDkgShareAcceptanceV1,
        GlobalThresholdBeaconDkgTranscriptV1, GlobalThresholdBeaconKeySessionV1,
        GlobalThresholdBeaconPartialSignatureProofV1, GlobalThresholdBeaconPartialSignatureV1,
        GlobalThresholdBeaconPublicShareV1, GlobalThresholdBeaconPulseContextV1,
    },
};
use iroha_model_base::peer::PeerId;
use mv::storage::StorageReadOnly;
use norito::{
    NoritoDeserialize, NoritoSerialize,
    codec::Encode as _,
    derive::{JsonDeserialize, JsonSerialize},
};
#[cfg(any(test, feature = "iroha-core-tests"))]
use rand::{SeedableRng as _, rngs::StdRng};
use std::{collections::BTreeMap, sync::RwLock};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(feature = "test-network-parliament-signers")]
#[doc(hidden)]
pub mod parliament_test_network_signer;

pub use iroha_data_model::sumeragi_finality::global_threshold_beacon_npos_successor_seed_v1;
use iroha_data_model::sumeragi_finality::{
    GLOBAL_BEACON_PULSE_PAYLOAD_DOMAIN_V1, GLOBAL_BEACON_PULSE_PAYLOAD_LEN_V1,
};
pub use iroha_data_model::sumeragi_finality::{
    global_threshold_beacon_pulse_id_v1, global_threshold_beacon_pulse_payload_v1,
};
const GLOBAL_BEACON_LANE_RELAY_SEED_DOMAIN_V1: &[u8] =
    b"iroha.global-threshold-beacon.lane-relay-seed.v1\0";
const GLOBAL_BEACON_GOVERNANCE_SEED_DOMAIN_V1: &[u8] =
    b"iroha.global-threshold-beacon.governance-seed.v1\0";

/// Canonical pulse-position round for the first-release beacon protocol.
///
/// Consensus views only route and retransmit partials. They never alter the
/// threshold-signed payload, preventing view-change grinding after a pulse is
/// observed.
pub const GLOBAL_THRESHOLD_BEACON_PULSE_ROUND_V1: u64 = 0;

/// Read the sole canonical active global-beacon key-session pointer.
///
/// The first-release state shape permits either no entry or exactly one entry
/// at its internal singleton key. Exposing this checked projection keeps
/// dependent crates from treating a corrupt storage key as authoritative.
///
/// # Errors
///
/// Returns [`GlobalThresholdBeaconError::PersistenceConflict`] when the
/// underlying singleton storage contains a noncanonical key or more than one
/// entry.
pub fn active_global_threshold_beacon_session_id_v1(
    world: &impl crate::state::WorldReadOnly,
) -> Result<Option<[u8; 32]>, GlobalThresholdBeaconError> {
    let mut entries = world.global_beacon_active_session().iter();
    let Some((key, session_id)) = entries.next() else {
        return Ok(None);
    };
    if *key != crate::state::GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY || entries.next().is_some() {
        return Err(GlobalThresholdBeaconError::PersistenceConflict);
    }
    Ok(Some(*session_id))
}

/// Hash the exact ordered, domainless validator identities used as DKG seats.
///
/// Consensus power is fixed to one in Sumeragi, so the public beacon
/// session binds the canonical `PeerId` roster rather than duplicating that
/// invariant in its DKG transcript.
#[must_use]
pub fn global_threshold_beacon_roster_hash_v1(roster: &[PeerId]) -> [u8; 32] {
    global_threshold_beacon_roster_hash_iter_v1(roster.iter())
}

/// Hash an exact ordered roster projection without collecting or cloning peer keys.
///
/// The iterator must preserve its order and contents when cloned for serialization.
#[must_use]
pub fn global_threshold_beacon_roster_hash_iter_v1<'a, I>(roster: I) -> [u8; 32]
where
    I: ExactSizeIterator<Item = &'a PeerId> + Clone,
{
    *iroha_crypto::HashOf::new(&validation::RosterIter(roster)).as_ref()
}

/// Authenticate a public beacon key against an exact ordered consensus roster.
///
/// The active-key pointer alone is insufficient: a stale or foreign DKG key
/// may still be well formed and produce valid threshold signatures. Every
/// producer and validator must therefore compare both the roster commitment
/// and its exact committee size with the authenticated height context.
///
/// # Errors
///
/// Returns [`GlobalThresholdBeaconError::RosterMismatch`] when the key session
/// does not name precisely the supplied ordered roster.
pub(crate) fn authenticated_global_threshold_beacon_roster_hash_v1(
    session: &GlobalThresholdBeaconKeySessionV1,
    roster: &[PeerId],
) -> Result<[u8; 32], GlobalThresholdBeaconError> {
    authenticated_global_threshold_beacon_roster_hash_iter_v1(session, roster.iter())
}

/// Authenticate exact ordered borrowed validator identities without key/vector copies.
pub(crate) fn authenticated_global_threshold_beacon_roster_hash_iter_v1<'a, I>(
    session: &GlobalThresholdBeaconKeySessionV1,
    roster: I,
) -> Result<[u8; 32], GlobalThresholdBeaconError>
where
    I: ExactSizeIterator<Item = &'a PeerId> + Clone,
{
    let count = roster.len();
    let roster_hash = global_threshold_beacon_roster_hash_iter_v1(roster);
    if session.roster_hash != roster_hash || usize::from(session.committee_size) != count {
        return Err(GlobalThresholdBeaconError::RosterMismatch);
    }
    Ok(roster_hash)
}

/// Exact external bindings required when admitting a global beacon key session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalThresholdBeaconSessionBindingV1 {
    /// Exact deployment identity derived from genesis.
    pub network_id: NetworkId,
    /// Expected unique beacon session identifier.
    pub session_id: [u8; 32],
    /// Expected hash of the frozen ordered validator roster.
    pub roster_hash: [u8; 32],
    /// Expected commitment to the complete public DKG transcript.
    pub transcript_hash: [u8; 32],
}

/// Authoritative monotonic ingestion cursor for finalized pulses.
///
/// The cursor is not part of any later pulse's signed message or seed. It only
/// records the latest admitted slot so persistence can reject late insertion
/// while permitting intentionally skipped optional heights.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::beacon::GlobalThresholdBeaconPulseLinkV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
)]
pub struct GlobalThresholdBeaconPulseLinkV1 {
    /// Identifier of the latest admitted pulse or genesis origin.
    pub pulse_id: [u8; 32],
    /// Seed of the latest admitted pulse or genesis origin.
    pub seed: [u8; 32],
    /// Latest admitted consensus height.
    pub height: u64,
    /// Latest admitted protocol round.
    pub round: u64,
}

impl GlobalThresholdBeaconPulseLinkV1 {
    /// Validate a non-zero persisted ingestion cursor.
    pub fn validate(self) -> Result<(), GlobalThresholdBeaconError> {
        if is_zero(&self.pulse_id) || is_zero(&self.seed) {
            return Err(GlobalThresholdBeaconError::ZeroPulse);
        }
        Ok(())
    }

    /// Validate the genesis-supplied origin used before the first pulse.
    pub fn validate_origin(self) -> Result<(), GlobalThresholdBeaconError> {
        self.validate()?;
        if self.height != 0 || self.round != 0 {
            return Err(GlobalThresholdBeaconError::NonMonotonicPosition);
        }
        Ok(())
    }
}

/// Signed preimage for one exact DKG recipient encryption key.
#[must_use]
pub fn global_threshold_beacon_dkg_recipient_key_preimage_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    key: &GlobalThresholdBeaconDkgRecipientKeyV1,
) -> Vec<u8> {
    validation::DkgSignaturePreimage::RecipientKey(session, key).encode_exact()
}

/// Exact signed recipient-key identity used in private-edge associated data.
#[must_use]
pub fn global_threshold_beacon_dkg_recipient_key_hash_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    key: &GlobalThresholdBeaconDkgRecipientKeyV1,
) -> [u8; 32] {
    *iroha_crypto::HashOf::new(&validation::DkgRecordPreimage {
        domain: b"iroha.global-threshold-beacon.dkg-recipient-key-hash.v1\0",
        session,
        record: key,
    })
    .as_ref()
}

/// Signed preimage for a dealer's complete coefficient broadcast.
#[must_use]
pub fn global_threshold_beacon_dkg_dealer_commitment_preimage_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    commitment: &GlobalThresholdBeaconDkgDealerCommitmentV1,
) -> Vec<u8> {
    validation::DkgSignaturePreimage::DealerCommitment(session, commitment).encode_exact()
}

/// Verify the dealer-seat signature on one exact public commitment.
///
/// # Errors
/// Rejects a forged seat, session, coefficient vector or proof broadcast.
/// Verification borrows its inputs and retains no signature cache.
pub fn verify_global_threshold_beacon_dkg_dealer_commitment_signature_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    dealer_key: &GlobalThresholdBeaconDkgRecipientKeyV1,
    commitment: &GlobalThresholdBeaconDkgDealerCommitmentV1,
) -> Result<(), GlobalThresholdBeaconError> {
    validation::unbudgeted(
        verify_global_threshold_beacon_dkg_dealer_commitment_signature_v1_with(
            session,
            dealer_key,
            commitment,
            &mut validation::AllocatingSignatureVerifier::new(&mut |_| {
                Ok::<_, std::convert::Infallible>(())
            }),
        ),
    )
}

fn verify_global_threshold_beacon_dkg_dealer_commitment_signature_v1_with<
    V: validation::DkgSignatureVerifier,
>(
    session: &GlobalThresholdBeaconDkgSessionV1,
    dealer_key: &GlobalThresholdBeaconDkgRecipientKeyV1,
    commitment: &GlobalThresholdBeaconDkgDealerCommitmentV1,
    verifier: &mut V,
) -> Result<(), GlobalThresholdBeaconVerificationError<V::Resource>> {
    if dealer_key.recipient_index != commitment.dealer_index
        || !verifier
            .verify(
                validation::DkgSignaturePreimage::DealerCommitment(session, commitment),
                &commitment.signature,
                dealer_key.validator.public_key(),
            )
            .map_err(GlobalThresholdBeaconVerificationError::Resource)?
    {
        return Err(GlobalThresholdBeaconError::DealerCommitmentEquivocation.into());
    }
    Ok(())
}

/// Canonical AEAD associated data for one encrypted dealer-to-recipient edge.
#[must_use]
pub fn global_threshold_beacon_dkg_private_edge_aad_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    edge: &GlobalThresholdBeaconDkgEncryptedShareV1,
) -> Vec<u8> {
    validation::DkgSignaturePreimage::PrivateEdgeAad(session, edge).encode_exact()
}

/// Signed preimage for the complete encrypted private edge.
#[must_use]
pub fn global_threshold_beacon_dkg_encrypted_share_preimage_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    edge: &GlobalThresholdBeaconDkgEncryptedShareV1,
) -> Vec<u8> {
    validation::DkgSignaturePreimage::EncryptedShare(session, edge).encode_exact()
}

/// Stable hash of a signed private edge without revealing its plaintext.
#[must_use]
pub fn global_threshold_beacon_dkg_encrypted_share_hash_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    edge: &GlobalThresholdBeaconDkgEncryptedShareV1,
) -> [u8; 32] {
    *iroha_crypto::HashOf::new(&validation::DkgRecordPreimage {
        domain: b"iroha.global-threshold-beacon.dkg-encrypted-share-hash.v1\0",
        session,
        record: edge,
    })
    .as_ref()
}

/// Signed preimage for one recipient's exact dealer edge acceptance.
#[must_use]
pub fn global_threshold_beacon_dkg_share_acceptance_preimage_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    acceptance: &GlobalThresholdBeaconDkgShareAcceptanceV1,
) -> Vec<u8> {
    validation::DkgSignaturePreimage::ShareAcceptance(session, acceptance).encode_exact()
}

/// Verify a target seat's signed, attempt-bound hybrid encryption key.
///
/// # Errors
/// Rejects an invalid seat, non-BLS owner, malformed hybrid key or signature.
pub fn verify_global_threshold_beacon_dkg_recipient_key_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    key: &GlobalThresholdBeaconDkgRecipientKeyV1,
) -> Result<(), GlobalThresholdBeaconError> {
    validation::unbudgeted(verify_global_threshold_beacon_dkg_recipient_key_v1_with(
        session,
        key,
        &mut validation::AllocatingSignatureVerifier::new(&mut |_| {
            Ok::<_, std::convert::Infallible>(())
        }),
    ))
}

fn verify_global_threshold_beacon_dkg_recipient_key_v1_with<V: validation::DkgSignatureVerifier>(
    session: &GlobalThresholdBeaconDkgSessionV1,
    key: &GlobalThresholdBeaconDkgRecipientKeyV1,
    verifier: &mut V,
) -> Result<(), GlobalThresholdBeaconVerificationError<V::Resource>> {
    validate_participant(session, key.recipient_index)?;
    if key.validator.public_key().algorithm() != Algorithm::BlsNormal
        || iroha_crypto::hybrid::HybridPublicKey::validate_bytes(
            &key.x25519_public_key,
            &key.mlkem768_public_key,
        )
        .is_err()
        || !verifier
            .verify(
                validation::DkgSignaturePreimage::RecipientKey(session, key),
                &key.signature,
                key.validator.public_key(),
            )
            .map_err(GlobalThresholdBeaconVerificationError::Resource)?
    {
        return Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey.into());
    }
    Ok(())
}

/// Verify the public signed envelope of one encrypted private DKG edge.
///
/// # Errors
/// Rejects a foreign recipient key, dealer, commitment, phase or signature.
pub fn verify_global_threshold_beacon_dkg_encrypted_share_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    dealer: &GlobalThresholdBeaconDkgDealerCommitmentV1,
    dealer_key: &GlobalThresholdBeaconDkgRecipientKeyV1,
    recipient_key: &GlobalThresholdBeaconDkgRecipientKeyV1,
    edge: &GlobalThresholdBeaconDkgEncryptedShareV1,
) -> Result<(), GlobalThresholdBeaconError> {
    validation::unbudgeted(verify_global_threshold_beacon_dkg_encrypted_share_v1_with(
        session,
        dealer,
        dealer_key,
        recipient_key,
        edge,
        &mut validation::AllocatingSignatureVerifier::new(&mut |_| {
            Ok::<_, std::convert::Infallible>(())
        }),
    ))
}

fn verify_global_threshold_beacon_dkg_encrypted_share_v1_with<
    V: validation::DkgSignatureVerifier,
>(
    session: &GlobalThresholdBeaconDkgSessionV1,
    dealer: &GlobalThresholdBeaconDkgDealerCommitmentV1,
    dealer_key: &GlobalThresholdBeaconDkgRecipientKeyV1,
    recipient_key: &GlobalThresholdBeaconDkgRecipientKeyV1,
    edge: &GlobalThresholdBeaconDkgEncryptedShareV1,
    verifier: &mut V,
) -> Result<(), GlobalThresholdBeaconVerificationError<V::Resource>> {
    if edge.dealer_index != dealer.dealer_index
        || edge.dealer_index != dealer_key.recipient_index
        || edge.recipient_index != recipient_key.recipient_index
        || edge.dealer_commitment_hash
            != global_threshold_beacon_dkg_dealer_commitment_hash_v1(session, dealer)
        || edge.recipient_key_hash
            != global_threshold_beacon_dkg_recipient_key_hash_v1(session, recipient_key)
        || edge.delivery_height < session.commitments_end_height
        || edge.delivery_height >= session.deliveries_end_height
        || edge.encrypted_share.len() != 12 + 96 + 16
        || iroha_crypto::hybrid::HybridKemCiphertext::validate_parts(
            &edge.ephemeral_x25519_public_key,
            &edge.mlkem768_ciphertext,
        )
        .is_err()
        || !verifier
            .verify(
                validation::DkgSignaturePreimage::EncryptedShare(session, edge),
                &edge.signature,
                dealer_key.validator.public_key(),
            )
            .map_err(GlobalThresholdBeaconVerificationError::Resource)?
    {
        return Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare.into());
    }
    Ok(())
}

/// Verify one exact recipient acceptance without exposing a private share.
///
/// # Errors
/// Rejects changed session, commitment, recipient or acceptance signature.
pub fn verify_global_threshold_beacon_dkg_share_acceptance_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    dealer: &GlobalThresholdBeaconDkgDealerCommitmentV1,
    recipient: &GlobalThresholdBeaconDkgRecipientKeyV1,
    acceptance: &GlobalThresholdBeaconDkgShareAcceptanceV1,
) -> Result<(), GlobalThresholdBeaconError> {
    validation::unbudgeted(verify_global_threshold_beacon_dkg_share_acceptance_v1_with(
        session,
        dealer,
        recipient,
        acceptance,
        &mut validation::AllocatingSignatureVerifier::new(&mut |_| {
            Ok::<_, std::convert::Infallible>(())
        }),
    ))
}

fn verify_global_threshold_beacon_dkg_share_acceptance_v1_with<
    V: validation::DkgSignatureVerifier,
>(
    session: &GlobalThresholdBeaconDkgSessionV1,
    dealer: &GlobalThresholdBeaconDkgDealerCommitmentV1,
    recipient: &GlobalThresholdBeaconDkgRecipientKeyV1,
    acceptance: &GlobalThresholdBeaconDkgShareAcceptanceV1,
    verifier: &mut V,
) -> Result<(), GlobalThresholdBeaconVerificationError<V::Resource>> {
    if acceptance.dealer_index != dealer.dealer_index
        || acceptance.recipient_index != recipient.recipient_index
        || acceptance.dealer_commitment_hash
            != global_threshold_beacon_dkg_dealer_commitment_hash_v1(session, dealer)
        || acceptance.encrypted_share_hash == [0; 32]
        || acceptance.accepted_height < session.deliveries_end_height
        || acceptance.accepted_height >= session.acceptances_end_height
        || !verifier
            .verify(
                validation::DkgSignaturePreimage::ShareAcceptance(session, acceptance),
                &acceptance.signature,
                recipient.validator.public_key(),
            )
            .map_err(GlobalThresholdBeaconVerificationError::Resource)?
    {
        return Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance.into());
    }
    Ok(())
}

/// Public, replayable snapshot of an active all-edge DKG reducer.
///
/// Encrypted delivery envelopes and signed acceptances are public audit data;
/// plaintext private shares and threshold-signature partials have no field in
/// this type and cannot enter authoritative World persistence.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::beacon::GlobalThresholdBeaconDkgSnapshotV1")]
#[norito(decode_fields)]
pub struct GlobalThresholdBeaconDkgSnapshotV1 {
    /// Immutable DKG session and consensus-height schedule.
    pub session: GlobalThresholdBeaconDkgSessionV1,
    /// Purpose-separated Das--Ren `h` generator in canonical compressed G2 form.
    pub generator_h: [u8; 96],
    /// Purpose-separated Das--Ren `v` generator in canonical compressed G2 form.
    pub generator_v: [u8; 96],
    /// Attempt-bound recipient keys in strictly increasing seat order.
    pub recipient_keys: Vec<GlobalThresholdBeaconDkgRecipientKeyV1>,
    /// Dealer coefficient broadcasts in strictly increasing dealer order.
    pub dealer_commitments: Vec<GlobalThresholdBeaconDkgDealerCommitmentV1>,
    /// Signed encrypted private shares in canonical `(dealer, recipient)` order.
    pub encrypted_shares: Vec<GlobalThresholdBeaconDkgEncryptedShareV1>,
    /// Signed recipient acknowledgments in canonical `(dealer, recipient)` order.
    pub share_acceptances: Vec<GlobalThresholdBeaconDkgShareAcceptanceV1>,
    /// Greatest committed height consumed by this reducer snapshot.
    pub last_updated_height: u64,
}

impl GlobalThresholdBeaconDkgSnapshotV1 {
    /// Validate all non-secret persisted structure and canonical ordering.
    ///
    /// Cryptographic implementations must additionally restore this snapshot
    /// with [`GlobalThresholdBeaconDkgStateV1::from_snapshot`] before resuming it;
    /// that path re-derives the generators and verifies every public proof.
    pub fn validate(&self) -> Result<(), GlobalThresholdBeaconError> {
        validation::DkgSnapshotRef::from(self).validate()
    }
}

/// Finalized public beacon-key session with activation and retirement metadata.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::beacon::FinalizedGlobalThresholdBeaconKeySessionRecordV1")]
pub struct FinalizedGlobalThresholdBeaconKeySessionRecordV1 {
    /// Canonical finalized threshold-beacon session and full public transcript.
    pub session: GlobalThresholdBeaconKeySessionV1,
    /// Committed height at which this key became the active pulse signer.
    pub activated_at_height: Option<u64>,
    /// Committed height at which this key ceased being active.
    pub retired_at_height: Option<u64>,
}

impl FinalizedGlobalThresholdBeaconKeySessionRecordV1 {
    /// Construct a finalized but not-yet-active key lifecycle record.
    pub fn new(
        session: GlobalThresholdBeaconKeySessionV1,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        let record = Self {
            session,
            activated_at_height: None,
            retired_at_height: None,
        };
        record.validate(budget)?;
        Ok(record)
    }

    /// Validate the full public key transcript and lifecycle ordering.
    pub fn validate(
        &self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), GlobalThresholdBeaconSessionError> {
        let binding = GlobalThresholdBeaconSessionBindingV1 {
            network_id: self.session.network_id,
            session_id: self.session.session_id,
            roster_hash: self.session.roster_hash,
            transcript_hash: self.session.transcript_hash,
        };
        session_owner::verify_borrowed_session(&self.session, &binding, budget)?;
        session_owner::validate_lifecycle(
            self.session.adaptive_dkg.finalized_at_height,
            self.activated_at_height,
            self.retired_at_height,
        )?;
        Ok(())
    }

    /// Mark this key active at a committed height, idempotently at the same height.
    pub fn activate(
        &mut self,
        height: u64,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), GlobalThresholdBeaconSessionError> {
        if self.retired_at_height.is_some()
            || height < self.session.adaptive_dkg.finalized_at_height
        {
            return Err(GlobalThresholdBeaconError::InvalidKeyLifecycle.into());
        }
        self.validate(budget)?;
        match self.activated_at_height {
            Some(existing) if existing != height => {
                return Err(GlobalThresholdBeaconError::InvalidKeyLifecycle.into());
            }
            Some(_) => return Ok(()),
            None => self.activated_at_height = Some(height),
        }
        Ok(())
    }

    /// Mark this active key retired at a strictly later committed height.
    pub fn retire(
        &mut self,
        height: u64,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), GlobalThresholdBeaconSessionError> {
        let activated = self
            .activated_at_height
            .ok_or(GlobalThresholdBeaconError::InvalidKeyLifecycle)?;
        if height <= activated {
            return Err(GlobalThresholdBeaconError::InvalidKeyLifecycle.into());
        }
        self.validate(budget)?;
        match self.retired_at_height {
            Some(existing) if existing != height => {
                return Err(GlobalThresholdBeaconError::InvalidKeyLifecycle.into());
            }
            Some(_) => return Ok(()),
            None => self.retired_at_height = Some(height),
        }
        Ok(())
    }

    /// Return whether this record authorizes pulses at `height`.
    #[must_use]
    pub fn is_active_at(&self, height: u64) -> bool {
        self.activated_at_height
            .is_some_and(|start| start <= height)
            && self.retired_at_height.is_none_or(|end| height < end)
    }
}

/// Validation failures for global threshold-beacon sessions and pulses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GlobalThresholdBeaconError {
    /// The DTO does not use the sole first-release protocol version.
    #[error("unsupported global threshold-beacon version {actual}")]
    UnsupportedVersion {
        /// Version supplied by the DTO.
        actual: u16,
    },
    /// The canonical Norito envelope could not be decoded or re-encoded.
    #[error("invalid global threshold-beacon Norito envelope")]
    InvalidEncoding,
    /// The supplied bytes are not the unique canonical Norito encoding.
    #[error("non-canonical global threshold-beacon Norito encoding")]
    NonCanonicalEncoding,
    /// The pulse or session targets another genesis-derived network.
    #[error("global threshold-beacon network binding mismatch")]
    NetworkMismatch,
    /// The pulse or key uses another threshold-beacon session.
    #[error("global threshold-beacon session binding mismatch")]
    SessionMismatch,
    /// The pulse or key uses another frozen validator roster.
    #[error("global threshold-beacon roster binding mismatch")]
    RosterMismatch,
    /// The supplied public transcript does not match its computed or expected commitment.
    #[error("global threshold-beacon public transcript mismatch")]
    TranscriptMismatch,
    /// A required pulse identifier, seed, height, or finalized anchor is inert.
    #[error("global threshold-beacon pulse contains an inert zero binding")]
    ZeroPulse,
    /// The pulse position does not strictly follow the authoritative ingestion cursor.
    #[error("global threshold-beacon height/round is not strictly monotonic")]
    NonMonotonicPosition,
    /// A finalized pulse used a consensus-view-dependent round.
    #[error("global threshold-beacon pulse round is not the canonical fixed round")]
    NonCanonicalRound,
    /// The pulse does not authenticate the expected finalized-chain point.
    #[error("global threshold-beacon finalized-chain anchor mismatch")]
    FinalizedAnchorMismatch,
    /// The pulse changes its native instance, complete epoch or exact parent execution identity.
    #[error("global threshold-beacon native signing context mismatch")]
    PulseContextMismatch,
    /// The supplied seed is not the unique seed derived from the final signature.
    #[error("global threshold-beacon derived seed mismatch")]
    SeedMismatch,
    /// A pulse reused an already admitted identifier or slot.
    #[error("global threshold-beacon pulse reused an earlier result")]
    ReusedPulse,
    /// The supplied pulse ID is not its canonical computed identifier.
    #[error("global threshold-beacon pulse identifier mismatch")]
    PulseIdMismatch,
    /// DKG height windows or immutable bindings are inconsistent.
    #[error("invalid global threshold-beacon DKG session schedule or binding")]
    InvalidDkgSession,
    /// A DKG message names a participant outside the frozen committee.
    #[error("global threshold-beacon DKG participant index is outside the frozen committee")]
    InvalidDkgParticipant,
    /// A DKG event arrived outside its consensus-height phase.
    #[error("global threshold-beacon DKG event arrived in the wrong phase")]
    WrongDkgPhase,
    /// A dealer broadcast two different commitments for one session.
    #[error("global threshold-beacon DKG dealer commitment equivocation")]
    DealerCommitmentEquivocation,
    /// A target seat's attempt-bound encryption key is invalid or equivocated.
    #[error("invalid global threshold-beacon DKG recipient key")]
    InvalidDkgRecipientKey,
    /// An encrypted dealer-to-recipient edge is malformed, misbound or equivocated.
    #[error("invalid global threshold-beacon DKG encrypted share")]
    InvalidDkgEncryptedShare,
    /// A signed dealer-to-recipient edge acceptance is invalid or equivocated.
    #[error("invalid global threshold-beacon DKG share acceptance")]
    InvalidDkgShareAcceptance,
    /// One or more frozen dealer/recipient edges are absent at the cutoff.
    #[error("global threshold-beacon DKG lacks complete accepted edges")]
    IncompleteDkgEdges,
    /// The DKG state has already reached a terminal state.
    #[error("global threshold-beacon DKG is already terminal")]
    DkgTerminal,
    /// A persisted DKG snapshot moved its consensus high-water mark backwards.
    #[error("global threshold-beacon DKG snapshot height regressed")]
    NonMonotonicDkgState,
    /// Activation or retirement metadata is inconsistent with DKG finalization.
    #[error("invalid global threshold-beacon key lifecycle")]
    InvalidKeyLifecycle,
    /// Authoritative World persistence conflicts with an existing beacon record.
    #[error("conflicting global threshold-beacon persistent state")]
    PersistenceConflict,
    /// The active key pointer does not authorize the requested beacon operation.
    #[error("global threshold-beacon active key mismatch")]
    ActiveKeyMismatch,
    /// Persisted finalized pulse history or its latest link is inconsistent.
    #[error("invalid global threshold-beacon pulse history")]
    InvalidPulseHistory,
    /// One signer supplied two distinct, individually addressed partial signatures.
    #[error("global threshold-beacon partial-signature equivocation")]
    PartialSignatureEquivocation,
    /// The pulse reducer has not collected the session reconstruction threshold.
    #[error("insufficient verified global threshold-beacon partial signatures")]
    InsufficientPartialSignatures,
    /// Fixed-suite threshold-BLS validation failed.
    #[error(transparent)]
    ThresholdBls(#[from] ThresholdBlsError),
}

/// Distinguish an invalid beacon relation from a caller's resource refusal.
///
/// The resource value belongs to the caller; this verifier creates no budget,
/// decoder scope, or long-lived cache. Deterministic callers use `Infallible`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GlobalThresholdBeaconVerificationError<E = norito::core::DecodeResourceError> {
    /// The supplied session does not satisfy the canonical beacon relation.
    #[error(transparent)]
    Invalid(#[from] GlobalThresholdBeaconError),
    /// The caller declined an allocation before its backing was requested.
    #[error("global threshold-beacon verification resource admission refused")]
    Resource(E),
}

impl<E> From<ThresholdBlsError> for GlobalThresholdBeaconVerificationError<E> {
    fn from(error: ThresholdBlsError) -> Self {
        Self::Invalid(error.into())
    }
}

/// Consensus-height phase of an all-edge global beacon DKG run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalThresholdBeaconDkgPhaseV1 {
    /// The configured start height has not been reached.
    Pending,
    /// Dealers broadcast coefficient commitments and recipient encryption keys.
    Commitments,
    /// Dealers privately deliver encrypted share triples.
    Deliveries,
    /// Recipients publish signed acceptance of each exact private edge.
    Acceptances,
    /// The acceptance deadline passed and all edges can be checked.
    Finalizable,
    /// The session produced one canonical public transcript.
    Finalized,
    /// The session could not collect every frozen dealer/recipient edge.
    Aborted,
}

/// Public values derived by the adaptive crypto implementation at DKG finalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalThresholdBeaconDkgDerivedPublicV1 {
    /// Canonical compressed G2 group public key.
    pub group_public_key: [u8; 96],
    /// Composite verification keys with roster-and-index participant seat bindings.
    pub public_shares: arrayvec::ArrayVec<
        GlobalThresholdBeaconPublicShareV1,
        { THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize },
    >,
    /// Typed adaptive public-transcript commitment.
    pub transcript_hash: [u8; 32],
}

/// Narrow cryptographic boundary used by the consensus-owned DKG reducer.
///
/// Implementations must use the Das--Ren Figure-2/3/5 construction. In
/// particular, ordinary Feldman shares are not a conforming implementation.
pub trait GlobalThresholdBeaconDkgCryptoV1 {
    /// Derive independent, purpose-separated G2 generators `h` and `v`.
    fn derive_generators(
        &self,
        session: &GlobalThresholdBeaconDkgSessionV1,
    ) -> Result<([u8; 96], [u8; 96]), ThresholdBlsError>;

    /// Validate one complete dealer coefficient vector and constant-term PoK.
    fn verify_dealer_commitment(
        &self,
        session: &GlobalThresholdBeaconDkgSessionV1,
        generator_h: &[u8; 96],
        generator_v: &[u8; 96],
        commitment: &GlobalThresholdBeaconDkgDealerCommitmentV1,
    ) -> Result<(), ThresholdBlsError>;

    /// Derive the group key, all composite public shares, and ready transcript.
    fn finalize_qualified_dealers(
        &self,
        session: &GlobalThresholdBeaconDkgSessionV1,
        generator_h: &[u8; 96],
        generator_v: &[u8; 96],
        dealer_commitments: &[GlobalThresholdBeaconDkgDealerCommitmentV1],
        qualified_dealers: &[u16],
        event_hash: [u8; 32],
    ) -> Result<GlobalThresholdBeaconDkgDerivedPublicV1, ThresholdBlsError>;
}

/// Production adaptive threshold-BLS backend for the consensus DKG reducer.
///
/// This adapter owns public verification and transcript finalization only. It
/// never accepts, returns, clones, logs, or serializes a private dealer/share
/// object; zeroizing secret owners remain exclusively in `iroha_crypto` and the
/// authenticated DKG transport layer.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdaptiveGlobalThresholdBeaconDkgCryptoV1;

impl GlobalThresholdBeaconDkgCryptoV1 for AdaptiveGlobalThresholdBeaconDkgCryptoV1 {
    fn derive_generators(
        &self,
        session: &GlobalThresholdBeaconDkgSessionV1,
    ) -> Result<([u8; 96], [u8; 96]), ThresholdBlsError> {
        let parameters = adaptive_beacon_parameters(session)?;
        Ok((*parameters.h_bytes(), *parameters.v_bytes()))
    }

    fn verify_dealer_commitment(
        &self,
        session: &GlobalThresholdBeaconDkgSessionV1,
        generator_h: &[u8; 96],
        generator_v: &[u8; 96],
        commitment: &GlobalThresholdBeaconDkgDealerCommitmentV1,
    ) -> Result<(), ThresholdBlsError> {
        let parameters = adaptive_beacon_parameters(session)?;
        require_adaptive_generators(&parameters, generator_h, generator_v)?;
        verify_adaptive_dealer(&parameters, commitment)?;
        Ok(())
    }

    fn finalize_qualified_dealers(
        &self,
        session: &GlobalThresholdBeaconDkgSessionV1,
        generator_h: &[u8; 96],
        generator_v: &[u8; 96],
        dealer_commitments: &[GlobalThresholdBeaconDkgDealerCommitmentV1],
        qualified_dealers: &[u16],
        event_hash: [u8; 32],
    ) -> Result<GlobalThresholdBeaconDkgDerivedPublicV1, ThresholdBlsError> {
        let parameters = adaptive_beacon_parameters(session)?;
        require_adaptive_generators(&parameters, generator_h, generator_v)?;
        if dealer_commitments.len() > usize::from(session.committee_size)
            || qualified_dealers.len() > usize::from(session.committee_size)
            || dealer_commitments
                .windows(2)
                .any(|rows| rows[0].dealer_index >= rows[1].dealer_index)
        {
            return Err(ThresholdBlsError::NonCanonicalQualifiedSet);
        }
        let validated =
            dealer_commitments
                .iter()
                .map(|commitment| {
                    verify_adaptive_dealer(&parameters, commitment)
                        .map(|dealer| (commitment.dealer_index, dealer))
                })
                .collect::<Result<
                    arrayvec::ArrayVec<_, { THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize }>,
                    _,
                >>()?;
        let qualified =
            qualified_dealers
                .iter()
                .map(|index| {
                    validated
                        .iter()
                        .find(|(seat, _)| seat == index)
                        .map(|(_, dealer)| dealer.clone())
                        .ok_or(ThresholdBlsError::NonCanonicalQualifiedSet)
                })
                .collect::<Result<
                    arrayvec::ArrayVec<_, { THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize }>,
                    _,
                >>()?;
        let transcript = AdaptiveThresholdBlsPublicTranscript::from_qualified_dealers(
            &parameters,
            &qualified,
            qualified_dealers,
            event_hash,
        )?;
        Ok(GlobalThresholdBeaconDkgDerivedPublicV1 {
            group_public_key: *transcript.group_public_key().as_bytes(),
            public_shares: transcript
                .public_shares()
                .iter()
                .map(|share| GlobalThresholdBeaconPublicShareV1 {
                    index: share.index(),
                    // This is H(typed session, roster commitment, one-based seat),
                    // not an independently supplied identity digest.
                    participant_seat_binding: *share.participant_hash(),
                    public_key_share: *share.as_bytes(),
                })
                .collect(),
            transcript_hash: *transcript.transcript_hash(),
        })
    }
}

fn adaptive_beacon_parameters(
    session: &GlobalThresholdBeaconDkgSessionV1,
) -> Result<AdaptiveThresholdBlsParameters<BeaconPurpose>, ThresholdBlsError> {
    let typed_session = ThresholdBlsSession::<BeaconPurpose>::new(
        *session.network_id.as_bytes(),
        session.session_id,
        session.roster_hash,
        session.committee_size,
        session.threshold,
    )?;
    AdaptiveThresholdBlsParameters::derive(&typed_session)
}

fn require_adaptive_generators(
    parameters: &AdaptiveThresholdBlsParameters<BeaconPurpose>,
    generator_h: &[u8; 96],
    generator_v: &[u8; 96],
) -> Result<(), ThresholdBlsError> {
    if parameters.h_bytes() != generator_h || parameters.v_bytes() != generator_v {
        return Err(ThresholdBlsError::InvalidAdaptiveGenerator);
    }
    Ok(())
}

fn verify_adaptive_dealer(
    parameters: &AdaptiveThresholdBlsParameters<BeaconPurpose>,
    commitment: &GlobalThresholdBeaconDkgDealerCommitmentV1,
) -> Result<ValidatedDealerCommitment<BeaconPurpose>, ThresholdBlsError> {
    DasRenDealerCommitment::verify(
        parameters,
        commitment.dealer_index,
        &commitment.coefficient_commitments,
        commitment.constant_term_proof.commitment,
        commitment.constant_term_proof.response,
    )
}

/// Deterministic consensus reducer for the public phases of adaptive beacon DKG.
pub struct GlobalThresholdBeaconDkgStateV1 {
    budget: iroha_allocation::AllocationBudget,
    session: GlobalThresholdBeaconDkgSessionV1,
    generator_h: [u8; 96],
    generator_v: [u8; 96],
    recipient_keys: DkgRows<GlobalThresholdBeaconDkgRecipientKeyV1>,
    dealer_commitments: DkgRows<GlobalThresholdBeaconDkgDealerCommitmentV1>,
    encrypted_shares: DkgRows<GlobalThresholdBeaconDkgEncryptedShareV1>,
    share_acceptances: DkgRows<GlobalThresholdBeaconDkgShareAcceptanceV1>,
    finalized: Option<iroha_allocation::RetainedPayload<GlobalThresholdBeaconKeySessionV1>>,
    aborted: bool,
    last_updated_height: u64,
}

impl std::fmt::Debug for GlobalThresholdBeaconDkgStateV1 {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("GlobalThresholdBeaconDkgStateV1")
            .field("session", &self.session)
            .field("recipient_keys", &self.recipient_keys)
            .field("dealer_commitments", &self.dealer_commitments)
            .field("encrypted_shares", &self.encrypted_shares)
            .field("share_acceptances", &self.share_acceptances)
            .field(
                "finalized",
                &self
                    .finalized
                    .as_ref()
                    .map(iroha_allocation::RetainedPayload::get),
            )
            .field("aborted", &self.aborted)
            .field("last_updated_height", &self.last_updated_height)
            .finish()
    }
}

impl GlobalThresholdBeaconDkgStateV1 {
    /// Check the immutable authenticated geometry/generators without constructing mutable state.
    ///
    /// # Errors
    /// Rejects an invalid committee, threshold, schedule or cryptographic generator pair.
    pub fn validate_session(
        session: &GlobalThresholdBeaconDkgSessionV1,
        crypto: &impl GlobalThresholdBeaconDkgCryptoV1,
    ) -> Result<(), GlobalThresholdBeaconError> {
        validate_dkg_session(session)?;
        let (h, v) = crypto.derive_generators(session)?;
        if is_zero(&h) || is_zero(&v) || h == v {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession);
        }
        Ok(())
    }

    /// Start one DKG reducer after validating its immutable schedule and generators.
    pub fn new(
        session: GlobalThresholdBeaconDkgSessionV1,
        crypto: &impl GlobalThresholdBeaconDkgCryptoV1,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        validate_dkg_session(&session)?;
        let (generator_h, generator_v) = crypto.derive_generators(&session)?;
        if is_zero(&generator_h) || is_zero(&generator_v) || generator_h == generator_v {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        let seats = usize::from(session.committee_size);
        let edges = seats
            .checked_mul(seats)
            .ok_or(iroha_allocation::AllocationRefusal::DemandOverflow)?;
        let mut reservation = budget.try_reserve_layouts([
            DkgRows::<GlobalThresholdBeaconDkgRecipientKeyV1>::layout(seats)?,
            DkgRows::<GlobalThresholdBeaconDkgDealerCommitmentV1>::layout(seats)?,
            DkgRows::<GlobalThresholdBeaconDkgEncryptedShareV1>::layout(edges)?,
            DkgRows::<GlobalThresholdBeaconDkgShareAcceptanceV1>::layout(edges)?,
        ])?;
        let recipient_keys = DkgRows::from_reservation(seats, &mut reservation)?;
        let dealer_commitments = DkgRows::from_reservation(seats, &mut reservation)?;
        let encrypted_shares = DkgRows::from_reservation(edges, &mut reservation)?;
        let share_acceptances = DkgRows::from_reservation(edges, &mut reservation)?;
        let last_updated_height = session.start_height.saturating_sub(1);
        Ok(Self {
            budget: budget.clone(),
            session,
            generator_h,
            generator_v,
            recipient_keys,
            dealer_commitments,
            encrypted_shares,
            share_acceptances,
            finalized: None,
            aborted: false,
            last_updated_height,
        })
    }

    /// Restore one public snapshot, re-deriving generators and re-verifying all
    /// public dealer proofs, signed keys, envelopes, and acceptances before the
    /// reducer can consume another event.
    pub fn from_snapshot(
        snapshot: &GlobalThresholdBeaconDkgSnapshotV1,
        crypto: &impl GlobalThresholdBeaconDkgCryptoV1,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        let mut workspace = DkgMessageWorkspace::for_snapshot(snapshot, budget)?;
        validation::DkgSnapshotRef::from(snapshot).validate_with_verifier(&mut workspace)?;
        let (generator_h, generator_v) = crypto.derive_generators(&snapshot.session)?;
        if generator_h != snapshot.generator_h || generator_v != snapshot.generator_v {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        for commitment in &snapshot.dealer_commitments {
            crypto.verify_dealer_commitment(
                &snapshot.session,
                &generator_h,
                &generator_v,
                commitment,
            )?;
        }
        let mut state = Self::new(snapshot.session, crypto, budget)?;
        for row in &snapshot.recipient_keys {
            state.recipient_keys.insert(row, budget)?;
        }
        for row in &snapshot.dealer_commitments {
            state.dealer_commitments.insert(row, budget)?;
        }
        for row in &snapshot.encrypted_shares {
            state.encrypted_shares.insert(row, budget)?;
        }
        for row in &snapshot.share_acceptances {
            state.share_acceptances.insert(row, budget)?;
        }
        state.last_updated_height = snapshot.last_updated_height;
        Ok(state)
    }

    /// Return the canonical public-only persistence projection of this active reducer.
    pub fn public_snapshot(
        &self,
    ) -> Result<RetainedGlobalThresholdBeaconDkgSnapshotV1, GlobalThresholdBeaconSessionError> {
        if self.finalized.is_some() || self.aborted {
            return Err(GlobalThresholdBeaconError::DkgTerminal.into());
        }
        let snapshot = RetainedGlobalThresholdBeaconDkgSnapshotV1::from_rows(
            self.session,
            self.generator_h,
            self.generator_v,
            &self.recipient_keys,
            &self.dealer_commitments,
            &self.encrypted_shares,
            &self.share_acceptances,
            self.last_updated_height,
            &self.budget,
        )?;
        let mut workspace = DkgMessageWorkspace::for_snapshot(snapshot.record(), &self.budget)?;
        validation::DkgSnapshotRef::from(snapshot.record())
            .validate_with_verifier(&mut workspace)?;
        Ok(snapshot)
    }

    /// Move the completed graph and its exact ledger out of the consumed reducer.
    ///
    /// # Errors
    /// Rejects an unfinished or cancelled attempt. No copy or allocation occurs.
    pub fn into_finalized(
        mut self,
    ) -> Result<RetainedGlobalThresholdBeaconDkgFinalizationV1, GlobalThresholdBeaconSessionError>
    {
        let owner = self
            .finalized
            .take()
            .ok_or(GlobalThresholdBeaconError::DkgTerminal)?;
        Ok(RetainedGlobalThresholdBeaconDkgFinalizationV1 { owner })
    }

    /// Original caller operation pool, shared by every phase and public projection.
    pub fn allocation_budget(&self) -> &iroha_allocation::AllocationBudget {
        &self.budget
    }

    /// Return this reducer's immutable session identifier.
    #[must_use]
    pub fn session_id(&self) -> [u8; 32] {
        self.session.session_id
    }

    fn require_monotonic_height(&self, height: u64) -> Result<(), GlobalThresholdBeaconError> {
        if height < self.last_updated_height {
            return Err(GlobalThresholdBeaconError::NonMonotonicDkgState);
        }
        Ok(())
    }

    /// Return the phase implied by committed height and terminal reducer state.
    #[must_use]
    pub fn phase_at(&self, height: u64) -> GlobalThresholdBeaconDkgPhaseV1 {
        if self.finalized.is_some() {
            return GlobalThresholdBeaconDkgPhaseV1::Finalized;
        }
        if self.aborted {
            return GlobalThresholdBeaconDkgPhaseV1::Aborted;
        }
        if height < self.session.start_height {
            GlobalThresholdBeaconDkgPhaseV1::Pending
        } else if height < self.session.commitments_end_height {
            GlobalThresholdBeaconDkgPhaseV1::Commitments
        } else if height < self.session.deliveries_end_height {
            GlobalThresholdBeaconDkgPhaseV1::Deliveries
        } else if height < self.session.acceptances_end_height {
            GlobalThresholdBeaconDkgPhaseV1::Acceptances
        } else {
            GlobalThresholdBeaconDkgPhaseV1::Finalizable
        }
    }

    /// Admit one exact target seat's signed recipient key during commitments.
    pub fn record_recipient_key(
        &mut self,
        height: u64,
        key: &GlobalThresholdBeaconDkgRecipientKeyV1,
    ) -> Result<(), GlobalThresholdBeaconSessionError> {
        self.require_monotonic_height(height)?;
        if self.phase_at(height) != GlobalThresholdBeaconDkgPhaseV1::Commitments {
            return Err(GlobalThresholdBeaconError::WrongDkgPhase.into());
        }
        session_owner::validate_dkg_recipient_bounds(&self.session, key)?;
        let mut workspace = DkgMessageWorkspace::new(
            validation::DkgSignaturePreimage::RecipientKey(&self.session, key).encoded_len(),
            &self.budget,
        )?;
        verify_global_threshold_beacon_dkg_recipient_key_v1_with(
            &self.session,
            key,
            &mut workspace,
        )?;
        if let Some(existing) = self.recipient_keys.get(&key.recipient_index) {
            return if existing == key {
                self.last_updated_height = height;
                Ok(())
            } else {
                Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey.into())
            };
        }
        if self.recipient_keys.values().any(|existing| {
            existing.validator == key.validator
                || (existing.x25519_public_key == key.x25519_public_key
                    && existing.mlkem768_public_key == key.mlkem768_public_key)
        }) {
            return Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey.into());
        }
        let mut roster =
            arrayvec::ArrayVec::<&PeerId, { THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize }>::new();
        let mut inserted = false;
        for existing in self.recipient_keys.values() {
            if !inserted && key.recipient_index < existing.recipient_index {
                roster.push(&key.validator);
                inserted = true;
            }
            roster.push(&existing.validator);
        }
        if !inserted {
            roster.push(&key.validator);
        }
        if roster.len() == usize::from(self.session.committee_size)
            && global_threshold_beacon_roster_hash_iter_v1(roster.iter().copied())
                != self.session.roster_hash
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey.into());
        }
        // The projected roster borrows the old rows only through the hash check.
        drop(roster);
        self.recipient_keys.insert(key, &self.budget)?;
        self.last_updated_height = height;
        Ok(())
    }

    /// Admit one dealer broadcast during the commitment window.
    pub fn record_dealer_commitment(
        &mut self,
        height: u64,
        commitment: &GlobalThresholdBeaconDkgDealerCommitmentV1,
        crypto: &impl GlobalThresholdBeaconDkgCryptoV1,
    ) -> Result<(), GlobalThresholdBeaconSessionError> {
        self.require_monotonic_height(height)?;
        if self.phase_at(height) != GlobalThresholdBeaconDkgPhaseV1::Commitments {
            return Err(GlobalThresholdBeaconError::WrongDkgPhase.into());
        }
        validate_participant(&self.session, commitment.dealer_index)?;
        let dealer_key = self
            .recipient_keys
            .get(&commitment.dealer_index)
            .ok_or(GlobalThresholdBeaconError::DealerCommitmentEquivocation)?;
        session_owner::validate_dkg_dealer_bounds(&self.session, commitment)?;
        let mut workspace = DkgMessageWorkspace::new(
            validation::DkgSignaturePreimage::DealerCommitment(&self.session, commitment)
                .encoded_len(),
            &self.budget,
        )?;
        verify_global_threshold_beacon_dkg_dealer_commitment_signature_v1_with(
            &self.session,
            dealer_key,
            commitment,
            &mut workspace,
        )?;
        if commitment.coefficient_commitments.len() != usize::from(self.session.threshold) {
            return Err(GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        if let Some(existing) = self.dealer_commitments.get(&commitment.dealer_index) {
            return if existing == commitment {
                self.last_updated_height = height;
                Ok(())
            } else {
                Err(GlobalThresholdBeaconError::DealerCommitmentEquivocation.into())
            };
        }
        crypto.verify_dealer_commitment(
            &self.session,
            &self.generator_h,
            &self.generator_v,
            &commitment,
        )?;
        self.dealer_commitments.insert(commitment, &self.budget)?;
        self.last_updated_height = height;
        Ok(())
    }

    /// Admit one signed private ciphertext during the delivery window.
    pub fn record_encrypted_share(
        &mut self,
        height: u64,
        edge: &GlobalThresholdBeaconDkgEncryptedShareV1,
    ) -> Result<(), GlobalThresholdBeaconSessionError> {
        self.require_monotonic_height(height)?;
        if self.phase_at(height) != GlobalThresholdBeaconDkgPhaseV1::Deliveries {
            return Err(GlobalThresholdBeaconError::WrongDkgPhase.into());
        }
        if edge.delivery_height != height {
            return Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare.into());
        }
        let dealer = self
            .dealer_commitments
            .get(&edge.dealer_index)
            .ok_or(GlobalThresholdBeaconError::InvalidDkgEncryptedShare)?;
        let dealer_key = self
            .recipient_keys
            .get(&edge.dealer_index)
            .ok_or(GlobalThresholdBeaconError::InvalidDkgEncryptedShare)?;
        let recipient_key = self
            .recipient_keys
            .get(&edge.recipient_index)
            .ok_or(GlobalThresholdBeaconError::InvalidDkgEncryptedShare)?;
        session_owner::validate_dkg_edge_bounds(edge)?;
        let mut workspace = DkgMessageWorkspace::new(
            validation::DkgSignaturePreimage::EncryptedShare(&self.session, edge).encoded_len(),
            &self.budget,
        )?;
        verify_global_threshold_beacon_dkg_encrypted_share_v1_with(
            &self.session,
            dealer,
            dealer_key,
            recipient_key,
            edge,
            &mut workspace,
        )?;
        let key = (edge.dealer_index, edge.recipient_index);
        if let Some(existing) = self.encrypted_shares.get(&key) {
            return if existing == edge {
                self.last_updated_height = height;
                Ok(())
            } else {
                Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare.into())
            };
        }
        self.encrypted_shares.insert(edge, &self.budget)?;
        self.last_updated_height = height;
        Ok(())
    }

    /// Admit one signed acceptance only after private delivery has closed.
    pub fn record_share_acceptance(
        &mut self,
        height: u64,
        acceptance: &GlobalThresholdBeaconDkgShareAcceptanceV1,
    ) -> Result<(), GlobalThresholdBeaconSessionError> {
        self.require_monotonic_height(height)?;
        if self.phase_at(height) != GlobalThresholdBeaconDkgPhaseV1::Acceptances {
            return Err(GlobalThresholdBeaconError::WrongDkgPhase.into());
        }
        if acceptance.accepted_height != height {
            return Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance.into());
        }
        let dealer = self
            .dealer_commitments
            .get(&acceptance.dealer_index)
            .ok_or(GlobalThresholdBeaconError::InvalidDkgShareAcceptance)?;
        let recipient = self
            .recipient_keys
            .get(&acceptance.recipient_index)
            .ok_or(GlobalThresholdBeaconError::InvalidDkgShareAcceptance)?;
        let edge = self
            .encrypted_shares
            .get(&(acceptance.dealer_index, acceptance.recipient_index))
            .ok_or(GlobalThresholdBeaconError::InvalidDkgShareAcceptance)?;
        if acceptance.encrypted_share_hash
            != global_threshold_beacon_dkg_encrypted_share_hash_v1(&self.session, edge)
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance.into());
        }
        session_owner::validate_dkg_acceptance_bounds(acceptance)?;
        let mut workspace = DkgMessageWorkspace::new(
            validation::DkgSignaturePreimage::ShareAcceptance(&self.session, acceptance)
                .encoded_len(),
            &self.budget,
        )?;
        verify_global_threshold_beacon_dkg_share_acceptance_v1_with(
            &self.session,
            dealer,
            recipient,
            acceptance,
            &mut workspace,
        )?;
        let key = (acceptance.dealer_index, acceptance.recipient_index);
        if let Some(existing) = self.share_acceptances.get(&key) {
            return if existing == acceptance {
                self.last_updated_height = height;
                Ok(())
            } else {
                Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance.into())
            };
        }
        self.share_acceptances.insert(acceptance, &self.budget)?;
        self.last_updated_height = height;
        Ok(())
    }

    /// Finalize only after every frozen dealer/recipient edge is accepted.
    pub fn finalize(
        &mut self,
        height: u64,
        crypto: &impl GlobalThresholdBeaconDkgCryptoV1,
    ) -> Result<&GlobalThresholdBeaconKeySessionV1, GlobalThresholdBeaconSessionError> {
        self.require_monotonic_height(height)?;
        if self.finalized.is_some() || self.aborted {
            return Err(GlobalThresholdBeaconError::DkgTerminal.into());
        }
        if self.phase_at(height) != GlobalThresholdBeaconDkgPhaseV1::Finalizable {
            return Err(GlobalThresholdBeaconError::WrongDkgPhase.into());
        }
        let seats = usize::from(self.session.committee_size);
        let all_edges = seats
            .checked_mul(seats)
            .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?;
        if self.recipient_keys.len() != seats
            || self.dealer_commitments.len() != seats
            || self.encrypted_shares.len() != all_edges
            || self.share_acceptances.len() != all_edges
        {
            self.aborted = true;
            self.last_updated_height = height;
            return Err(GlobalThresholdBeaconError::IncompleteDkgEdges.into());
        }
        let qualified_dealers = (1..=self.session.committee_size)
            .collect::<arrayvec::ArrayVec<_, { THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize }>>();
        let snapshot = self.public_snapshot()?;
        let recipient_keys = &snapshot.recipient_keys;
        let dealer_commitments = &snapshot.dealer_commitments;
        let encrypted_shares = &snapshot.encrypted_shares;
        let share_acceptances = &snapshot.share_acceptances;
        let event_hash = global_threshold_beacon_dkg_event_hash_v1(
            &self.session,
            &self.generator_h,
            &self.generator_v,
            &recipient_keys,
            &dealer_commitments,
            &encrypted_shares,
            &share_acceptances,
            &qualified_dealers,
            height,
        );
        let derived = crypto.finalize_qualified_dealers(
            &self.session,
            &self.generator_h,
            &self.generator_v,
            &dealer_commitments,
            &qualified_dealers,
            event_hash,
        )?;
        if derived.public_shares.len() != usize::from(self.session.committee_size)
            || is_zero(&derived.transcript_hash)
        {
            return Err(GlobalThresholdBeaconError::TranscriptMismatch.into());
        }
        let finalized = session_owner::retain_finalized_dkg(
            snapshot.record(),
            &qualified_dealers,
            event_hash,
            height,
            &derived,
            &self.budget,
        )?;
        self.finalized = Some(finalized);
        self.last_updated_height = height;
        self.finalized
            .as_ref()
            .map(iroha_allocation::RetainedPayload::get)
            .ok_or_else(|| GlobalThresholdBeaconError::DkgTerminal.into())
    }
}

fn validate_dkg_session(
    session: &GlobalThresholdBeaconDkgSessionV1,
) -> Result<(), GlobalThresholdBeaconError> {
    if session.version != GLOBAL_THRESHOLD_BEACON_VERSION_V1
        || session.attempt_id == [0; 32]
        || is_zero(&session.roster_hash)
        || session.start_height >= session.commitments_end_height
        || session.commitments_end_height >= session.deliveries_end_height
        || session.deliveries_end_height >= session.acceptances_end_height
    {
        return Err(GlobalThresholdBeaconError::InvalidDkgSession);
    }
    ThresholdBlsSession::<BeaconPurpose>::new(
        *session.network_id.as_bytes(),
        session.session_id,
        session.roster_hash,
        session.committee_size,
        session.threshold,
    )?;
    Ok(())
}

fn validate_dkg_generators(
    session: &GlobalThresholdBeaconDkgSessionV1,
    generator_h: &[u8; 96],
    generator_v: &[u8; 96],
) -> Result<(), GlobalThresholdBeaconError> {
    if is_zero(generator_h) || is_zero(generator_v) || generator_h == generator_v {
        return Err(GlobalThresholdBeaconError::InvalidDkgSession);
    }
    let parameters = adaptive_beacon_parameters(session)?;
    require_adaptive_generators(&parameters, generator_h, generator_v)?;
    Ok(())
}

fn validate_participant(
    session: &GlobalThresholdBeaconDkgSessionV1,
    index: u16,
) -> Result<(), GlobalThresholdBeaconError> {
    if index == 0 || index > session.committee_size {
        return Err(GlobalThresholdBeaconError::InvalidDkgParticipant);
    }
    Ok(())
}

/// Compute the canonical identity of one dealer commitment in a typed DKG session.
#[must_use]
pub fn global_threshold_beacon_dkg_dealer_commitment_hash_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    commitment: &GlobalThresholdBeaconDkgDealerCommitmentV1,
) -> [u8; 32] {
    *iroha_crypto::HashOf::new(&validation::DkgRecordPreimage {
        domain: b"iroha.global-threshold-beacon.dkg-dealer.v1\0",
        session,
        record: commitment,
    })
    .as_ref()
}

/// Compute the canonical public-event transcript hash for DKG finalization.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn global_threshold_beacon_dkg_event_hash_v1(
    session: &GlobalThresholdBeaconDkgSessionV1,
    generator_h: &[u8; 96],
    generator_v: &[u8; 96],
    recipient_keys: &[GlobalThresholdBeaconDkgRecipientKeyV1],
    dealer_commitments: &[GlobalThresholdBeaconDkgDealerCommitmentV1],
    encrypted_shares: &[GlobalThresholdBeaconDkgEncryptedShareV1],
    share_acceptances: &[GlobalThresholdBeaconDkgShareAcceptanceV1],
    qualified_dealers: &[u16],
    finalized_at_height: u64,
) -> [u8; 32] {
    *iroha_crypto::HashOf::new(&validation::DkgEventPreimage {
        session,
        generator_h,
        generator_v,
        recipient_keys,
        dealer_commitments,
        encrypted_shares,
        share_acceptances,
        qualified_dealers,
        finalized_at_height,
    })
    .as_ref()
}

fn validate_adaptive_dkg_geometry(
    record: &GlobalThresholdBeaconKeySessionV1,
) -> Result<(), GlobalThresholdBeaconError> {
    let transcript = &record.adaptive_dkg;
    validate_dkg_session(&transcript.session)?;
    let session = &transcript.session;
    if session.version != record.version
        || session.network_id != record.network_id
        || session.session_id != record.session_id
        || session.roster_hash != record.roster_hash
        || session.committee_size != record.committee_size
        || session.threshold != record.threshold
        || transcript.finalized_at_height < session.acceptances_end_height
        || transcript.event_hash != record.dkg_contribution_hash
        || is_zero(&transcript.generator_h)
        || is_zero(&transcript.generator_v)
        || transcript.generator_h == transcript.generator_v
    {
        return Err(GlobalThresholdBeaconError::InvalidDkgSession);
    }

    let seats = usize::from(session.committee_size);
    let all_edges = seats
        .checked_mul(seats)
        .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?;
    if transcript.recipient_keys.len() != seats
        || transcript.dealer_commitments.len() != seats
        || transcript.encrypted_shares.len() != all_edges
        || transcript.share_acceptances.len() != all_edges
        || !transcript
            .qualified_dealers
            .iter()
            .copied()
            .eq(1..=session.committee_size)
    {
        return Err(GlobalThresholdBeaconError::IncompleteDkgEdges);
    }
    if record.public_shares.len() != seats {
        return Err(GlobalThresholdBeaconError::TranscriptMismatch);
    }
    validation::DkgSnapshotRef::from(transcript).validate_bounds()?;
    Ok(())
}

fn validate_adaptive_dkg_shape<V: validation::DkgSignatureVerifier>(
    record: &GlobalThresholdBeaconKeySessionV1,
    verifier: &mut V,
) -> Result<(), GlobalThresholdBeaconVerificationError<V::Resource>> {
    validate_adaptive_dkg_geometry(record)?;
    let transcript = &record.adaptive_dkg;
    let session = &transcript.session;
    validation::DkgSnapshotRef::from(transcript).validate_with_verifier(verifier)?;
    if global_threshold_beacon_dkg_event_hash_v1(
        session,
        &transcript.generator_h,
        &transcript.generator_v,
        &transcript.recipient_keys,
        &transcript.dealer_commitments,
        &transcript.encrypted_shares,
        &transcript.share_acceptances,
        &transcript.qualified_dealers,
        transcript.finalized_at_height,
    ) != transcript.event_hash
    {
        return Err(GlobalThresholdBeaconError::TranscriptMismatch.into());
    }
    Ok(())
}

fn reconstruct_adaptive_beacon_transcript(
    record: &GlobalThresholdBeaconKeySessionV1,
    validated_dealers: &mut iroha_allocation::ChargedBuffer<
        ValidatedDealerCommitment<BeaconPurpose>,
    >,
) -> Result<AdaptiveThresholdBlsPublicTranscript<BeaconPurpose>, GlobalThresholdBeaconError> {
    let public_dkg = &record.adaptive_dkg;
    ThresholdBlsPublicKey::<BeaconPurpose>::from_bytes(
        record.session_id,
        &record.group_public_key,
    )?;
    let parameters = adaptive_beacon_parameters(&public_dkg.session)?;
    require_adaptive_generators(
        &parameters,
        &public_dkg.generator_h,
        &public_dkg.generator_v,
    )?;
    // Every dealer uses fixed initialized coefficient storage. The complete outer
    // scratch buffer was prepaid with this original session attempt before work.
    for commitment in &public_dkg.dealer_commitments {
        validated_dealers.push_reserved(verify_adaptive_dealer(&parameters, commitment)?);
    }
    // The finalized index and public-share collections are inline and own no heap backing.
    let transcript = AdaptiveThresholdBlsPublicTranscript::from_qualified_dealers(
        &parameters,
        validated_dealers.as_slice(),
        &public_dkg.qualified_dealers,
        public_dkg.event_hash,
    )?;
    let reconstructed_shares = transcript.public_shares();
    if transcript.group_public_key().as_bytes() != &record.group_public_key
        || transcript.dkg_event_hash() != &record.dkg_contribution_hash
        || transcript.transcript_hash() != &record.transcript_hash
        || reconstructed_shares.len() != record.public_shares.len()
        || reconstructed_shares
            .iter()
            .zip(&record.public_shares)
            .any(|(actual, persisted)| {
                actual.index() != persisted.index
                    || actual.participant_hash() != &persisted.participant_seat_binding
                    || actual.as_bytes() != &persisted.public_key_share
            })
    {
        return Err(GlobalThresholdBeaconError::TranscriptMismatch.into());
    }
    Ok(transcript)
}

pub use session_owner::{
    GlobalThresholdBeaconSessionError, PreparedGlobalThresholdBeaconSessionVerificationV1,
    RetainedFinalizedGlobalThresholdBeaconSessionV1, ValidatedGlobalThresholdBeaconSessionV1,
};

/// Runtime-only owner capable of producing one adaptive beacon signature share.
///
/// Implementations are injected by the node's secure runtime boundary. They
/// must keep private DKG material out of configuration, World state, logs, and
/// wire DTOs. Every returned share is independently proof-verified by the
/// consensus reducer, so an unavailable or faulty provider can stop progress
/// but cannot inject unauthenticated randomness.
pub trait GlobalThresholdBeaconPartialSignerV1: Send + Sync {
    /// Attest live custody of the exact validated session and one-based signer seat.
    ///
    /// This performs no signing. Providers must query the same custody owner
    /// used by `sign_partial`; public transcript membership alone is insufficient.
    ///
    /// # Errors
    ///
    /// Returns a closed error for unavailable custody or a session/seat mismatch.
    fn attest_partial_signing_capability(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalThresholdBeaconCapabilityErrorV1,
    >;

    /// Sign the exact pulse payload for the supplied fully validated session.
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic when the requested session is absent,
    /// the provider cannot access its sealed share, or signing fails.
    fn sign_partial(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<GlobalThresholdBeaconPartialSignatureV1, String>;

    /// Prove exact prepared-seat custody in a domain distinct from consensus pulses.
    ///
    /// Providers that restrict their remote interface to typed pulse requests override this
    /// method with an independently validated readiness operation.
    ///
    /// # Errors
    /// Rejects inconsistent readiness contexts, unavailable custody or invalid share proofs.
    fn prove_seat_readiness(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        generation: &iroha_data_model::sumeragi::epoch::ValidatorGenerationV1,
        context: &iroha_data_model::nexus::ValidatorSeatReadinessContextV1,
    ) -> Result<
        GlobalThresholdBeaconPartialSignatureV1,
        seat_readiness::GlobalThresholdBeaconSeatReadinessErrorV1,
    > {
        seat_readiness::prove_with_partial_signer(self, session, generation, context)
    }

    /// Return whether the feature-isolated test daemon must corrupt this
    /// provider's outbound share after signing and before broadcast.
    ///
    /// This hook does not exist in ordinary builds. Its sole caller skips
    /// local reducer admission for the deliberately malformed share so the
    /// live network exercises receiver-side proof rejection without granting
    /// the faulty validator a hidden local contribution.
    #[cfg(feature = "test-network-parliament-signers")]
    #[doc(hidden)]
    fn test_network_emit_invalid_outbound_partial_v1(&self) -> bool {
        false
    }
}

/// Non-secret exact-session custody result from an authenticated runtime owner.
///
/// This value does not prove ledger activation or authorize a pulse. It must be
/// obtained through a live provider lookup and matched to the committed session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalThresholdBeaconPartialSigningCapabilityV1 {
    session_id: [u8; 32],
    transcript_hash: [u8; 32],
    signer_index: u16,
}

impl GlobalThresholdBeaconPartialSigningCapabilityV1 {
    /// Construct the public result after the provider has checked actual custody.
    ///
    /// # Errors
    ///
    /// Rejects a seat absent from the completely validated transcript.
    pub fn for_validated_session(
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        signer_index: u16,
    ) -> Result<Self, GlobalThresholdBeaconCapabilityErrorV1> {
        if !session
            .record()
            .public_shares
            .iter()
            .any(|share| share.index == signer_index)
        {
            return Err(GlobalThresholdBeaconCapabilityErrorV1::InvalidRequest);
        }
        Ok(Self {
            session_id: session.record().session_id,
            transcript_hash: session.record().transcript_hash,
            signer_index,
        })
    }

    /// Return the public key-session identity.
    #[must_use]
    pub const fn session_id(self) -> [u8; 32] {
        self.session_id
    }

    /// Return the exact public transcript hash.
    #[must_use]
    pub const fn transcript_hash(self) -> [u8; 32] {
        self.transcript_hash
    }

    /// Return the one-based signer seat.
    #[must_use]
    pub const fn signer_index(self) -> u16 {
        self.signer_index
    }

    /// Match the live result to the exact requested session and signer seat.
    #[must_use]
    pub fn matches(
        self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        signer_index: u16,
    ) -> bool {
        self.session_id == session.record().session_id
            && self.transcript_hash == session.record().transcript_hash
            && self.signer_index == signer_index
    }
}

/// Closed errors for non-signing global-beacon custody lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GlobalThresholdBeaconCapabilityErrorV1 {
    /// The secure runtime or authenticated lookup is unavailable.
    #[error("global beacon capability attestation is unavailable")]
    Unavailable,
    /// The exact session and signer seat are not owned by this provider.
    #[error("global beacon capability is not owned")]
    NotOwned,
    /// The requested seat is absent from the validated public transcript.
    #[error("global beacon capability request is invalid")]
    InvalidRequest,
}

/// Process-local zeroizing software owner for one adaptive beacon signing share.
///
/// This is an injection adapter for deployments whose secure runtime unwraps a
/// share into process memory. It deliberately has no `Clone`, `Debug`, byte
/// export, or serialization implementation. Deployment-owned providers may
/// instead implement [`GlobalThresholdBeaconPartialSignerV1`] directly.
pub struct InMemoryGlobalThresholdBeaconPartialSignerV1 {
    session: ValidatedGlobalThresholdBeaconSessionV1,
    share: AdaptiveThresholdBlsSecretShare<BeaconPurpose>,
}

impl InMemoryGlobalThresholdBeaconPartialSignerV1 {
    /// Move an adaptive share retained by the secure DKG runtime into the live
    /// signer without exporting or persisting its scalar components.
    ///
    /// # Errors
    ///
    /// Returns a threshold-beacon error when the share was constructed for a
    /// different public session or transcript.
    pub fn from_validated_share(
        session: ValidatedGlobalThresholdBeaconSessionV1,
        share: AdaptiveThresholdBlsSecretShare<BeaconPurpose>,
    ) -> Result<Self, GlobalThresholdBeaconError> {
        let import_challenge = Hash::new_from_chunks(&[
            b"iroha.global-threshold-beacon.runtime-share-import.v1\0",
            session.record().session_id.as_slice(),
            session.record().transcript_hash.as_slice(),
        ]);
        let partial = share.sign_payload(&session.transcript(), import_challenge.as_ref())?;
        session
            .transcript()
            .verify_partial_signature(import_challenge.as_ref(), &partial)?;
        Ok(Self { session, share })
    }

    /// Import one sealed share, validate it against the complete public DKG
    /// transcript, and consume the zeroizing component buffer.
    ///
    /// # Errors
    ///
    /// Returns a threshold-beacon validation error if the public session or
    /// secret share does not match the frozen transcript and participant seat.
    pub fn from_components(
        session: ValidatedGlobalThresholdBeaconSessionV1,
        signer_index: u16,
        components: Zeroizing<[[u8; 32]; 3]>,
    ) -> Result<Self, GlobalThresholdBeaconError> {
        let share = AdaptiveThresholdBlsSecretShare::from_components(
            &session.transcript(),
            signer_index,
            components[0],
            components[1],
            components[2],
        )?;
        Self::from_validated_share(session, share)
    }

    /// Return the one-based frozen DKG signer seat without exposing key material.
    #[must_use]
    pub const fn signer_index(&self) -> u16 {
        self.share.index()
    }

    /// Return the exact public DKG session owned by this adapter.
    #[must_use]
    pub fn session_id(&self) -> [u8; 32] {
        self.session.record().session_id
    }
}

impl GlobalThresholdBeaconPartialSignerV1 for InMemoryGlobalThresholdBeaconPartialSignerV1 {
    fn attest_partial_signing_capability(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalThresholdBeaconCapabilityErrorV1,
    > {
        let expected = GlobalThresholdBeaconPartialSigningCapabilityV1::for_validated_session(
            session,
            expected_signer_index,
        )?;
        if session.record() != self.session.record() || expected_signer_index != self.signer_index()
        {
            return Err(GlobalThresholdBeaconCapabilityErrorV1::NotOwned);
        }
        Ok(expected)
    }

    fn sign_partial(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<GlobalThresholdBeaconPartialSignatureV1, String> {
        if session.record() != self.session.record() {
            return Err(
                "requested global beacon session does not match the sealed share".to_owned(),
            );
        }
        self.share
            .sign_payload(&self.session.transcript(), payload)
            .map(|partial| global_threshold_beacon_partial_signature_dto_v1(&partial))
            .map_err(|error| format!("adaptive global beacon partial signing failed: {error}"))
    }
}

/// Process-local, zeroizing owner for active and retiring beacon signing shares.
///
/// The registry deliberately has no `Clone`, `Debug`, serialization, key-list,
/// or scalar-export surface. Exact-session lookup occurs under a read guard, so
/// a concurrent retirement waits until every in-flight signing call completes.
/// Removing a session synchronously drops its non-cloneable in-memory signer
/// and zeroizes the underlying adaptive scalar share.
pub struct RuntimeGlobalThresholdBeaconShareCustodyV1 {
    sessions: RwLock<BTreeMap<[u8; 32], InMemoryGlobalThresholdBeaconPartialSignerV1>>,
}

impl RuntimeGlobalThresholdBeaconShareCustodyV1 {
    /// Construct an empty, fail-closed runtime custody registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(BTreeMap::new()),
        }
    }

    /// Import one already-validated software share without implicit replacement.
    ///
    /// # Errors
    ///
    /// Returns a closed error if custody is unavailable or the exact key
    /// session is already present.
    pub fn insert_validated_share(
        &self,
        signer: InMemoryGlobalThresholdBeaconPartialSignerV1,
    ) -> Result<(), GlobalThresholdBeaconShareCustodyErrorV1> {
        let session_id = signer.session_id();
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| GlobalThresholdBeaconShareCustodyErrorV1::CustodyUnavailable)?;
        match sessions.entry(session_id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(signer);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(GlobalThresholdBeaconShareCustodyErrorV1::SessionAlreadyPresent)
            }
        }
    }

    /// Validate and import one zeroizing scalar triple for a public DKG session.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed public state, a mismatched share,
    /// duplicate custody, or an unavailable registry lock.
    pub fn import_components(
        &self,
        session: ValidatedGlobalThresholdBeaconSessionV1,
        signer_index: u16,
        components: Zeroizing<[[u8; 32]; 3]>,
    ) -> Result<(), GlobalThresholdBeaconShareCustodyErrorV1> {
        let signer = InMemoryGlobalThresholdBeaconPartialSignerV1::from_components(
            session,
            signer_index,
            components,
        )
        .map_err(|_| GlobalThresholdBeaconShareCustodyErrorV1::InvalidShare)?;
        self.insert_validated_share(signer)
    }

    /// Import scalar components against an exact public session committed by consensus.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the key session is not committed, its share
    /// is invalid, it is already held, or custody is unavailable.
    pub fn import_committed_components(
        &self,
        state: &impl crate::state::StateReadOnly,
        session_id: [u8; 32],
        signer_index: u16,
        components: Zeroizing<[[u8; 32]; 3]>,
    ) -> Result<(), GlobalThresholdBeaconShareCustodyErrorV1> {
        use crate::state::WorldReadOnly as _;
        let record = state
            .world()
            .global_beacon_key_sessions()
            .get(&session_id)
            .map(|record| record.session.clone())
            .ok_or(GlobalThresholdBeaconShareCustodyErrorV1::SessionNotCommitted)?;
        if record.session_id != session_id {
            return Err(GlobalThresholdBeaconShareCustodyErrorV1::SessionNotCommitted);
        }
        self.import_components(record, signer_index, components)
    }

    /// Retire and zeroize one share after consensus has retired that key session.
    ///
    /// A write guard waits for all current signing readers. The committed view
    /// must no longer name the session as active, its lifecycle must contain a
    /// retirement height, and the current committed height must be strictly
    /// later than that retirement boundary.
    ///
    /// # Errors
    ///
    /// Returns a closed error if committed state still permits use, the session
    /// is absent, or custody is unavailable.
    pub fn retire_session(
        &self,
        state: &impl crate::state::StateReadOnly,
        session_id: [u8; 32],
    ) -> Result<(), GlobalThresholdBeaconShareCustodyErrorV1> {
        use crate::state::{GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, WorldReadOnly as _};
        let committed_height = u64::try_from(state.height())
            .map_err(|_| GlobalThresholdBeaconShareCustodyErrorV1::InvalidCommittedState)?;
        if state
            .world()
            .global_beacon_active_session()
            .get(&GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY)
            == Some(&session_id)
        {
            return Err(GlobalThresholdBeaconShareCustodyErrorV1::SessionStillRequired);
        }
        let retired_at = state
            .world()
            .global_beacon_key_sessions()
            .get(&session_id)
            .and_then(|record| record.retired_at_height)
            .ok_or(GlobalThresholdBeaconShareCustodyErrorV1::SessionStillRequired)?;
        if committed_height <= retired_at {
            return Err(GlobalThresholdBeaconShareCustodyErrorV1::SessionStillRequired);
        }
        let retired = self
            .sessions
            .write()
            .map_err(|_| GlobalThresholdBeaconShareCustodyErrorV1::CustodyUnavailable)?
            .remove(&session_id)
            .ok_or(GlobalThresholdBeaconShareCustodyErrorV1::SessionNotPresent)?;
        drop(retired);
        Ok(())
    }
}

impl Default for RuntimeGlobalThresholdBeaconShareCustodyV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalThresholdBeaconPartialSignerV1 for RuntimeGlobalThresholdBeaconShareCustodyV1 {
    fn attest_partial_signing_capability(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalThresholdBeaconCapabilityErrorV1,
    > {
        GlobalThresholdBeaconPartialSigningCapabilityV1::for_validated_session(
            session,
            expected_signer_index,
        )?;
        let sessions = self
            .sessions
            .read()
            .map_err(|_| GlobalThresholdBeaconCapabilityErrorV1::Unavailable)?;
        let signer = sessions
            .get(&session.record().session_id)
            .ok_or(GlobalThresholdBeaconCapabilityErrorV1::NotOwned)?;
        signer.attest_partial_signing_capability(session, expected_signer_index)
    }

    fn sign_partial(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<GlobalThresholdBeaconPartialSignatureV1, String> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| "global threshold-beacon custody is unavailable".to_owned())?;
        let signer = sessions
            .get(&session.record().session_id)
            .ok_or_else(|| "global threshold-beacon share is unavailable".to_owned())?;
        signer.sign_partial(session, payload)
    }
}

/// Closed runtime beacon share-custody failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GlobalThresholdBeaconShareCustodyErrorV1 {
    /// The runtime custody lock was unavailable.
    #[error("global threshold-beacon custody is unavailable")]
    CustodyUnavailable,
    /// The imported scalar share or public transcript was invalid.
    #[error("global threshold-beacon share is invalid")]
    InvalidShare,
    /// The exact key session is already held and cannot be replaced implicitly.
    #[error("global threshold-beacon session is already present")]
    SessionAlreadyPresent,
    /// The exact key session is not held by this process.
    #[error("global threshold-beacon session is not present")]
    SessionNotPresent,
    /// Consensus state does not contain the requested public key session.
    #[error("global threshold-beacon public key session is not committed")]
    SessionNotCommitted,
    /// The supplied committed view cannot support a safe retirement decision.
    #[error("committed state is invalid for global threshold-beacon retirement")]
    InvalidCommittedState,
    /// Consensus still permits this key session to be used.
    #[error("global threshold-beacon session is still required")]
    SessionStillRequired,
}

/// Convert one locally produced adaptive signature share into its wire DTO.
///
/// The returned DTO is still only a partial signature. A receiver must admit it
/// through [`GlobalThresholdBeaconPulseAggregatorV1::accept_partial`], which
/// reconstructs canonical points and verifies the complete representation proof
/// against the exact pulse payload and public DKG session.
#[must_use]
pub fn global_threshold_beacon_partial_signature_dto_v1(
    partial: &DasRenPartialSignature<BeaconPurpose>,
) -> GlobalThresholdBeaconPartialSignatureV1 {
    let (z_s, z_r, z_u) = partial.response_bytes();
    GlobalThresholdBeaconPartialSignatureV1 {
        session_id: *partial.session_id(),
        signer_index: partial.index(),
        signature_share: *partial.sigma_bytes(),
        proof: GlobalThresholdBeaconPartialSignatureProofV1 {
            x: *partial.proof_x_bytes(),
            y: *partial.proof_y_bytes(),
            z_s: *z_s,
            z_r: *z_r,
            z_u: *z_u,
        },
    }
}

fn adaptive_partial_signature_from_dto_v1(
    partial: &GlobalThresholdBeaconPartialSignatureV1,
) -> Result<DasRenPartialSignature<BeaconPurpose>, GlobalThresholdBeaconError> {
    Ok(DasRenPartialSignature::from_bytes(
        partial.session_id,
        partial.signer_index,
        partial.signature_share,
        partial.proof.x,
        partial.proof.y,
        partial.proof.z_s,
        partial.proof.z_r,
        partial.proof.z_u,
    )?)
}

// The global threshold-beacon profile fixes n = 3f + 1 <= 31 and t = f + 1.
// These bounds follow the crypto profile, not the larger generic lane committee bound.
const GLOBAL_BEACON_PARTIAL_SLOTS: usize = THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize;
const GLOBAL_BEACON_MAX_THRESHOLD: usize = (GLOBAL_BEACON_PARTIAL_SLOTS - 1) / 3 + 1;

/// Session- and pulse-bound reducer for adaptive threshold-beacon partials.
///
/// Only proof-verified partial signatures enter this reducer. Signer indices are
/// kept in fixed canonical seat slots, retransmissions of the same signature share
/// are idempotent even when their zero-knowledge proof uses fresh randomness,
/// and a second distinct signature share from one signer fails closed as
/// equivocation. Payload storage, admitted partials and reconstruction selection
/// are bounded inline; transcript ownership and cryptographic scratch still require
/// their own allocation admission. Final reconstruction uses the lexicographically
/// first threshold of signer indices; the final BLS signature and seed are unique for every valid
/// threshold subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalThresholdBeaconPulseAggregatorV1 {
    session: ValidatedGlobalThresholdBeaconSessionV1,
    pulse: FinalizedGlobalThresholdBeaconPulseV1,
    payload: [u8; GLOBAL_BEACON_PULSE_PAYLOAD_LEN_V1],
    partials: [Option<DasRenPartialSignature<BeaconPurpose>>; GLOBAL_BEACON_PARTIAL_SLOTS],
}

impl GlobalThresholdBeaconPulseAggregatorV1 {
    /// Open one exact height-bound pulse against a validated public DKG session.
    ///
    /// The finalized-chain anchor must be the block immediately before the pulse
    /// height. Its hash is supplied by the consensus finalized-chain journal and
    /// is covered by every partial signature. The mandatory native context also binds the
    /// complete epoch, consensus parent and original parent execution result.
    pub fn new(
        session: ValidatedGlobalThresholdBeaconSessionV1,
        height: u64,
        finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1,
        context: GlobalThresholdBeaconPulseContextV1,
    ) -> Result<Self, GlobalThresholdBeaconError> {
        session.ensure_adaptive_protocol_ready()?;
        let crypto_session = session.transcript().session();
        if usize::from(crypto_session.committee_size()) > GLOBAL_BEACON_PARTIAL_SLOTS {
            return Err(ThresholdBlsError::InvalidCommitteeSize.into());
        }
        if !(1..=GLOBAL_BEACON_MAX_THRESHOLD).contains(&usize::from(crypto_session.threshold())) {
            return Err(ThresholdBlsError::InvalidThreshold.into());
        }
        context
            .validate()
            .map_err(|_| GlobalThresholdBeaconError::PulseContextMismatch)?;
        if height == 0 {
            return Err(GlobalThresholdBeaconError::NonMonotonicPosition);
        }
        if finalized_chain_anchor.height.checked_add(1) != Some(height)
            || is_zero(finalized_chain_anchor.block_hash.as_ref())
        {
            return Err(GlobalThresholdBeaconError::FinalizedAnchorMismatch);
        }

        let record = session.record();
        let pulse = FinalizedGlobalThresholdBeaconPulseV1 {
            version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id: record.network_id,
            session_id: record.session_id,
            roster_hash: record.roster_hash,
            transcript_hash: record.transcript_hash,
            context,
            height,
            round: GLOBAL_THRESHOLD_BEACON_PULSE_ROUND_V1,
            finalized_chain_anchor,
            signature: [0; 48],
            seed: [0; 32],
            pulse_id: [0; 32],
        };
        let payload = global_threshold_beacon_pulse_payload_v1(&pulse);
        Ok(Self {
            session,
            pulse,
            payload,
            partials: [None; GLOBAL_BEACON_PARTIAL_SLOTS],
        })
    }

    /// Return the immutable fully consuming payload signed in this round.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Borrow the proof-revalidated public key session for this pulse.
    #[must_use]
    pub const fn session(&self) -> &ValidatedGlobalThresholdBeaconSessionV1 {
        &self.session
    }

    /// Return the number of distinct proof-verified signer shares admitted.
    #[must_use]
    pub fn verified_partial_count(&self) -> usize {
        self.partials.iter().flatten().count()
    }

    /// Verify and admit one authenticated partial-signature DTO.
    ///
    /// Returns `true` for a newly admitted signer and `false` when the same
    /// verified signature share is retried, including with fresh proof randomness.
    pub fn accept_partial(
        &mut self,
        partial: GlobalThresholdBeaconPartialSignatureV1,
    ) -> Result<bool, GlobalThresholdBeaconError> {
        if partial.session_id != self.pulse.session_id {
            return Err(GlobalThresholdBeaconError::SessionMismatch);
        }
        if !(1..=self.session.transcript().session().committee_size())
            .contains(&partial.signer_index)
        {
            return Err(ThresholdBlsError::InvalidParticipantIndex.into());
        }
        let partial = adaptive_partial_signature_from_dto_v1(&partial)?;
        // HC59: a well-formed point is not an authenticated share. No seat slot
        // changes until its complete session/payload representation proof passes.
        #[cfg(not(all(test, sumeragi_core_mutation = "HC59")))]
        self.session
            .transcript()
            .verify_partial_signature(&self.payload, &partial)?;
        let slot = self
            .partials
            .get_mut(usize::from(partial.index() - 1))
            .ok_or(ThresholdBlsError::InvalidParticipantIndex)?;
        match slot {
            Some(previous) if previous.sigma_bytes() == partial.sigma_bytes() => Ok(false),
            Some(_) => Err(GlobalThresholdBeaconError::PartialSignatureEquivocation),
            None => {
                *slot = Some(partial);
                Ok(true)
            }
        }
    }

    /// Reconstruct, final-verify, and return the unique public pulse.
    pub fn finalize(
        &self,
    ) -> Result<FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconError> {
        let threshold = usize::from(self.session.transcript().session().threshold());
        if self.verified_partial_count() < threshold {
            return Err(GlobalThresholdBeaconError::InsufficientPartialSignatures);
        }
        let first = self
            .partials
            .iter()
            .flatten()
            .next()
            .copied()
            .ok_or(GlobalThresholdBeaconError::InsufficientPartialSignatures)?;
        // Seed the bounded scratch with an actual verified share. Only the fully
        // overwritten threshold prefix enters interpolation; there are no inert
        // cryptographic placeholders or heap-backed reconstruction subsets.
        let mut canonical_subset = [first; GLOBAL_BEACON_MAX_THRESHOLD];
        let canonical_subset = canonical_subset
            .get_mut(..threshold)
            .ok_or(ThresholdBlsError::InvalidThreshold)?;
        for (target, partial) in canonical_subset
            .iter_mut()
            .zip(self.partials.iter().flatten())
        {
            *target = *partial;
        }
        let signature = self
            .session
            .transcript()
            .combine_partial_signatures(&self.payload, canonical_subset)?;
        let mut pulse = self.pulse;
        pulse.signature = *signature.as_bytes();
        pulse.seed = self
            .session
            .transcript()
            .finalized_seed(&self.payload, &signature)?;
        pulse.pulse_id = global_threshold_beacon_pulse_id_v1(&pulse, pulse.seed);
        verify_finalized_global_threshold_beacon_pulse_v1(
            &self.session,
            &pulse,
            self.pulse.finalized_chain_anchor,
            &self.pulse.context,
        )?;
        Ok(pulse)
    }
}

/// Return the exact complete control, graph, ledger and verification-scratch demand.
///
/// This borrowed shape preflight grants no authentication or memory authority.
/// The prepaid constructor checks the same immutable source and its complete
/// original reservation again before any allocation; callers must retain that
/// original reservation rather than treating the byte count as a new allowance.
///
/// # Errors
/// Returns typed binding/geometry errors or an arithmetic layout refusal.
pub fn global_threshold_beacon_session_allocation_bytes_v1(
    record: &GlobalThresholdBeaconKeySessionV1,
    expected: &GlobalThresholdBeaconSessionBindingV1,
) -> Result<usize, GlobalThresholdBeaconSessionError> {
    ValidatedGlobalThresholdBeaconSessionV1::allocation_bytes(record, expected)
}

/// Validate and retain one borrowed canonical session from the caller's original pool.
///
/// The complete graph, shared control and actual verifier buffers are admitted
/// before construction. Invalid protocol relations and original resource refusals
/// remain distinct. The source stays untouched on every result; successful clones
/// share the identical sealed graph without repeating transcript verification.
///
/// # Errors
/// Returns a typed invalid relation, original admission refusal or concrete physical
/// construction failure. No resource failure substitutes another pool or release source.
pub fn validate_global_threshold_beacon_session_v1(
    record: &GlobalThresholdBeaconKeySessionV1,
    expected: &GlobalThresholdBeaconSessionBindingV1,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<ValidatedGlobalThresholdBeaconSessionV1, GlobalThresholdBeaconSessionError> {
    ValidatedGlobalThresholdBeaconSessionV1::admit(record, expected, budget)
}

/// Validate through an already prepaid original operation reservation.
///
/// Uses the same sealed constructor as the budget entry. Foreign pools and short
/// remainders refuse before destination allocation; construction consumes only
/// actual split charges, leaving unspent remainder with the caller. A partial
/// failure destroys its allocations before refunding their same-pool charges.
///
/// # Errors
/// Returns the exact typed relation, original reservation or physical construction failure.
pub fn validate_global_threshold_beacon_session_from_reservation_v1(
    record: &GlobalThresholdBeaconKeySessionV1,
    expected: &GlobalThresholdBeaconSessionBindingV1,
    budget: &iroha_allocation::AllocationBudget,
    reservation: &mut iroha_allocation::AllocationReservation,
) -> Result<ValidatedGlobalThresholdBeaconSessionV1, GlobalThresholdBeaconSessionError> {
    ValidatedGlobalThresholdBeaconSessionV1::admit_prepaid(record, expected, budget, reservation)
}

/// Decode and validate one canonical Norito key-session envelope.
///
/// # Errors
///
/// Distinguishes malformed/canonical input from original decoder-resource refusal
/// and original-pool session admission. Raw decoder/encoder backing still requires
/// its separate physical owner; the session reservation does not claim that work.
pub fn decode_global_threshold_beacon_session_v1(
    encoded: &[u8],
    expected: &GlobalThresholdBeaconSessionBindingV1,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<ValidatedGlobalThresholdBeaconSessionV1, GlobalThresholdBeaconSessionError> {
    let record: GlobalThresholdBeaconKeySessionV1 =
        norito::decode_from_bytes(encoded).map_err(|error| {
            let original_local = norito::core::decode_error_matches_active_limits(&error)
                || matches!(
                    error.decode_resource_error(),
                    Some(norito::core::DecodeResourceError::AllocationFailed { .. })
                );
            if !cfg!(all(test, sumeragi_core_mutation = "HC88")) && original_local {
                GlobalThresholdBeaconSessionError::DecodeResource(error)
            } else {
                GlobalThresholdBeaconError::InvalidEncoding.into()
            }
        })?;
    let canonical =
        norito::to_bytes(&record).map_err(GlobalThresholdBeaconSessionError::Encoding)?;
    if canonical != encoded {
        return Err(GlobalThresholdBeaconError::NonCanonicalEncoding.into());
    }
    validate_global_threshold_beacon_session_v1(&record, expected, budget)
}

/// Public slot recovered from one canonical threshold-beacon signing payload.
///
/// This is the credential-free projection used when a runtime signer lives
/// behind the authenticated provider broker. The complete public key session
/// travels alongside it; no private DKG component is included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalThresholdBeaconPulseSigningSlotV1 {
    /// Exact finalized height whose pulse is being produced.
    pub height: u64,
    /// Complete independently supplied native context covered by the signing payload.
    pub context: GlobalThresholdBeaconPulseContextV1,
    /// Exact finalized parent authenticated by the pulse.
    pub finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1,
}

/// Recover and validate the exact public slot from a beacon signing payload.
///
/// The parser accepts only the fixed V1 payload length, canonical fixed round,
/// and a byte-for-byte payload reconstructed from `session`, `height`, the complete native
/// context and the finalized-chain anchor. This prevents a broker client from using the beacon
/// provider as a generic threshold-BLS signing oracle.
///
/// # Errors
///
/// Returns a closed threshold-beacon error for a truncated, extended, foreign,
/// view-dependent, or otherwise noncanonical payload.
pub fn global_threshold_beacon_pulse_signing_slot_v1(
    session: &ValidatedGlobalThresholdBeaconSessionV1,
    payload: &[u8],
) -> Result<GlobalThresholdBeaconPulseSigningSlotV1, GlobalThresholdBeaconError> {
    let expected_len = GLOBAL_BEACON_PULSE_PAYLOAD_DOMAIN_V1.len() + 2 + 32 * 9 + 8 * 4;
    if payload.len() != expected_len {
        return Err(GlobalThresholdBeaconError::InvalidEncoding);
    }
    let context_offset = GLOBAL_BEACON_PULSE_PAYLOAD_DOMAIN_V1.len() + 2 + 32 * 4;
    let instance_end = context_offset + 32;
    let epoch_end = instance_end + 8;
    let epoch_context_end = epoch_end + 32;
    let parent_hash_end = epoch_context_end + 32;
    let parent_result_end = parent_hash_end + 32;
    let context = GlobalThresholdBeaconPulseContextV1 {
        instance: payload[context_offset..instance_end]
            .try_into()
            .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?,
        epoch: u64::from_be_bytes(
            payload[instance_end..epoch_end]
                .try_into()
                .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?,
        ),
        epoch_context_id: payload[epoch_end..epoch_context_end]
            .try_into()
            .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?,
        parent_consensus_hash: payload[epoch_context_end..parent_hash_end]
            .try_into()
            .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?,
        parent_result: payload[parent_hash_end..parent_result_end]
            .try_into()
            .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?,
    };
    let height_offset = payload.len() - (8 * 3 + 32);
    let round_offset = height_offset + 8;
    let anchor_height_offset = round_offset + 8;
    let anchor_hash_offset = anchor_height_offset + 8;
    let height = u64::from_be_bytes(
        payload[height_offset..round_offset]
            .try_into()
            .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?,
    );
    let round = u64::from_be_bytes(
        payload[round_offset..anchor_height_offset]
            .try_into()
            .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?,
    );
    if round != GLOBAL_THRESHOLD_BEACON_PULSE_ROUND_V1 {
        return Err(GlobalThresholdBeaconError::NonCanonicalRound);
    }
    let anchor_height = u64::from_be_bytes(
        payload[anchor_height_offset..anchor_hash_offset]
            .try_into()
            .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?,
    );
    let anchor_hash: [u8; 32] = payload[anchor_hash_offset..]
        .try_into()
        .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?;
    let finalized_chain_anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: anchor_height,
        block_hash: iroha_crypto::HashOf::from_untyped_unchecked(Hash::prehashed(anchor_hash)),
    };
    let reconstructed = GlobalThresholdBeaconPulseAggregatorV1::new(
        session.clone(),
        height,
        finalized_chain_anchor,
        context,
    )?;
    if reconstructed.payload() != payload {
        return Err(GlobalThresholdBeaconError::InvalidEncoding);
    }
    Ok(GlobalThresholdBeaconPulseSigningSlotV1 {
        height,
        context,
        finalized_chain_anchor,
    })
}

/// Derive one lane-relay committee seed from an already-verified global pulse.
#[must_use]
pub fn global_threshold_beacon_lane_relay_seed_v1(
    pulse: &FinalizedGlobalThresholdBeaconPulseV1,
    block_height: u64,
    dataspace_id: u64,
    lane_id: u32,
) -> [u8; 32] {
    *Hash::new_from_chunks(&[
        GLOBAL_BEACON_LANE_RELAY_SEED_DOMAIN_V1,
        pulse.network_id.as_bytes(),
        pulse.session_id.as_slice(),
        pulse.pulse_id.as_slice(),
        pulse.seed.as_slice(),
        pulse.height.to_be_bytes().as_slice(),
        block_height.to_be_bytes().as_slice(),
        dataspace_id.to_be_bytes().as_slice(),
        lane_id.to_be_bytes().as_slice(),
    ])
    .as_ref()
}

/// Derive a governance-sortition seed from an already-verified global pulse.
#[must_use]
pub fn global_threshold_beacon_governance_seed_v1(
    pulse: &FinalizedGlobalThresholdBeaconPulseV1,
    epoch: u64,
) -> [u8; 32] {
    *Hash::new_from_chunks(&[
        GLOBAL_BEACON_GOVERNANCE_SEED_DOMAIN_V1,
        pulse.network_id.as_bytes(),
        pulse.session_id.as_slice(),
        pulse.pulse_id.as_slice(),
        pulse.seed.as_slice(),
        pulse.height.to_be_bytes().as_slice(),
        epoch.to_be_bytes().as_slice(),
    ])
    .as_ref()
}

/// Re-verify a persisted pulse before deriving Parliament sortition/release entropy.
///
/// This is the restored-state trust boundary for governance: an authenticated
/// snapshot or storage image is not treated as a substitute for public DKG and
/// final threshold-signature verification.
///
/// # Errors
///
/// Returns a threshold-beacon error when the stored pulse is absent, belongs
/// to another network or height, references an invalid key session, or fails
/// final signature/seed verification.
pub(crate) fn verified_persisted_global_threshold_beacon_governance_seed_v1(
    world: &impl crate::state::WorldReadOnly,
    network_id: &NetworkId,
    pulse: FinalizedGlobalThresholdBeaconPulseV1,
    height: u64,
) -> Result<[u8; 32], GlobalThresholdBeaconError> {
    if pulse.height != height {
        return Err(GlobalThresholdBeaconError::InvalidPulseHistory);
    }
    let pulse = verified_persisted_global_threshold_beacon_pulse_v1(world, network_id, pulse)?;
    Ok(global_threshold_beacon_governance_seed_v1(&pulse, height))
}

/// Validate the canonical public shape of a persisted finalized pulse.
///
/// This checks all inert/replay bindings, the compressed signature encoding,
/// and the deterministic identifier. Full BLS verification remains mandatory
/// in [`verify_finalized_global_threshold_beacon_pulse_v1`] before insertion.
pub(crate) fn validate_persisted_global_threshold_beacon_pulse_v1(
    pulse: &FinalizedGlobalThresholdBeaconPulseV1,
) -> Result<GlobalThresholdBeaconPulseLinkV1, GlobalThresholdBeaconError> {
    iroha_data_model::sumeragi_finality::validate_beacon_pulse_shape(pulse).map_err(|error| {
        use iroha_data_model::sumeragi_finality::BeaconPulseShapeError;
        match error {
            BeaconPulseShapeError::PulseContextMismatch => {
                GlobalThresholdBeaconError::PulseContextMismatch
            }
            BeaconPulseShapeError::UnsupportedVersion { actual } => {
                GlobalThresholdBeaconError::UnsupportedVersion { actual }
            }
            BeaconPulseShapeError::NonCanonicalRound => {
                GlobalThresholdBeaconError::NonCanonicalRound
            }
            BeaconPulseShapeError::ZeroPulse => GlobalThresholdBeaconError::ZeroPulse,
            BeaconPulseShapeError::Signature(error) => error.into(),
            BeaconPulseShapeError::PulseIdMismatch => GlobalThresholdBeaconError::PulseIdMismatch,
        }
    })?;
    Ok(GlobalThresholdBeaconPulseLinkV1 {
        pulse_id: pulse.pulse_id,
        seed: pulse.seed,
        height: pulse.height,
        round: pulse.round,
    })
}

/// Verify one decoded finalized pulse against authoritative session and chain state.
///
/// # Errors
///
/// Returns [`GlobalThresholdBeaconError`] for an inert/replayed/nonmonotonic
/// pulse, any binding mismatch, malformed signature, signature failure, or a
/// non-canonical derived seed/identifier.
pub fn verify_finalized_global_threshold_beacon_pulse_v1(
    session: &ValidatedGlobalThresholdBeaconSessionV1,
    pulse: &FinalizedGlobalThresholdBeaconPulseV1,
    expected_anchor: GlobalThresholdBeaconChainAnchorV1,
    expected_context: &GlobalThresholdBeaconPulseContextV1,
) -> Result<GlobalThresholdBeaconPulseLinkV1, GlobalThresholdBeaconError> {
    expected_context
        .validate()
        .map_err(|_| GlobalThresholdBeaconError::PulseContextMismatch)?;
    if &pulse.context != expected_context {
        return Err(GlobalThresholdBeaconError::PulseContextMismatch);
    }
    if pulse.version != GLOBAL_THRESHOLD_BEACON_VERSION_V1 {
        return Err(GlobalThresholdBeaconError::UnsupportedVersion {
            actual: pulse.version,
        });
    }
    if pulse.round != GLOBAL_THRESHOLD_BEACON_PULSE_ROUND_V1 {
        return Err(GlobalThresholdBeaconError::NonCanonicalRound);
    }
    let session_record = session.record();
    if pulse.network_id != session_record.network_id {
        return Err(GlobalThresholdBeaconError::NetworkMismatch);
    }
    if pulse.session_id != session_record.session_id {
        return Err(GlobalThresholdBeaconError::SessionMismatch);
    }
    if pulse.roster_hash != session_record.roster_hash {
        return Err(GlobalThresholdBeaconError::RosterMismatch);
    }
    if pulse.transcript_hash != session_record.transcript_hash {
        return Err(GlobalThresholdBeaconError::TranscriptMismatch);
    }
    if pulse.height == 0
        || is_zero(&pulse.pulse_id)
        || is_zero(&pulse.seed)
        || is_zero(pulse.finalized_chain_anchor.block_hash.as_ref())
    {
        return Err(GlobalThresholdBeaconError::ZeroPulse);
    }
    if pulse.finalized_chain_anchor != expected_anchor {
        return Err(GlobalThresholdBeaconError::FinalizedAnchorMismatch);
    }

    let signature =
        ThresholdBlsSignature::<BeaconPurpose>::from_bytes(pulse.session_id, &pulse.signature)?;
    let payload = global_threshold_beacon_pulse_payload_v1(pulse);
    let seed = session.transcript().finalized_seed(&payload, &signature)?;
    session.ensure_adaptive_protocol_ready()?;
    if is_zero(&seed) || seed != pulse.seed {
        return Err(GlobalThresholdBeaconError::SeedMismatch);
    }
    let pulse_id = global_threshold_beacon_pulse_id_v1(pulse, seed);
    if pulse_id != pulse.pulse_id {
        return Err(GlobalThresholdBeaconError::PulseIdMismatch);
    }
    Ok(GlobalThresholdBeaconPulseLinkV1 {
        pulse_id,
        seed,
        height: pulse.height,
        round: pulse.round,
    })
}

/// Re-verify one persisted global pulse and its complete public DKG session.
pub(crate) fn verified_persisted_global_threshold_beacon_pulse_v1(
    world: &impl crate::state::WorldReadOnly,
    network_id: &NetworkId,
    pulse: FinalizedGlobalThresholdBeaconPulseV1,
) -> Result<FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconError> {
    if world.global_beacon_pulses().get(&pulse.pulse_id) != Some(&pulse)
        || world.global_beacon_pulse_slots().get(&(
            iroha_data_model::governance::types::BeaconSessionId::for_network_v1(&pulse.network_id),
            pulse.height,
        )) != Some(&pulse.pulse_id)
        || pulse.network_id != *network_id
        || pulse.finalized_chain_anchor.height.checked_add(1) != Some(pulse.height)
    {
        return Err(GlobalThresholdBeaconError::InvalidPulseHistory);
    }
    let key_record = world
        .global_beacon_key_sessions()
        .get(&pulse.session_id)
        .ok_or(GlobalThresholdBeaconError::ActiveKeyMismatch)?;
    if !key_record.is_active_at(pulse.height) {
        return Err(GlobalThresholdBeaconError::ActiveKeyMismatch);
    }
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: *network_id,
        session_id: pulse.session_id,
        roster_hash: pulse.roster_hash,
        transcript_hash: pulse.transcript_hash,
    };
    let session = &key_record.session;
    session.check_binding(&binding)?;
    let verified = verify_finalized_global_threshold_beacon_pulse_v1(
        &session,
        &pulse,
        pulse.finalized_chain_anchor,
        // The exact pulse row is already authenticated by this committed World. This helper
        // rechecks crypto only; it does not confer authority on an external native source.
        &pulse.context,
    )?;
    if validate_persisted_global_threshold_beacon_pulse_v1(&pulse)? != verified {
        return Err(GlobalThresholdBeaconError::InvalidPulseHistory);
    }
    Ok(pulse)
}

/// Re-verify the newest persisted global pulse at or before a block height.
///
/// Selection is deterministic and fails closed if restored state contains two
/// pulses at the selected height. The returned pulse is then checked against
/// its complete public DKG session and final threshold signature.
///
/// # Errors
///
/// Returns a threshold-beacon error when no eligible pulse exists, the selected
/// height is ambiguous, or the selected pulse fails persisted-state, session,
/// signature, seed, or identifier verification.
pub fn verified_global_threshold_beacon_pulse_at_or_before_v1(
    world: &impl crate::state::WorldReadOnly,
    network_id: &NetworkId,
    maximum_height: u64,
) -> Result<FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconError> {
    let mut selected = None;
    for (_, candidate) in world.global_beacon_pulses().iter() {
        if candidate.height > maximum_height {
            continue;
        }
        match selected {
            None => selected = Some(*candidate),
            Some(current) if candidate.height > current.height => selected = Some(*candidate),
            Some(current) if candidate.height == current.height => {
                return Err(GlobalThresholdBeaconError::InvalidPulseHistory);
            }
            Some(_) => {}
        }
    }
    let pulse = selected.ok_or(GlobalThresholdBeaconError::InvalidPulseHistory)?;
    verified_persisted_global_threshold_beacon_pulse_v1(world, network_id, pulse)
}

/// Re-verify the latest persisted global pulse and its complete public session.
///
/// This is the shared read boundary for deterministic consumers outside the
/// Sumeragi epoch transition. The pulse must be the unique history tail and
/// must not come from the future relative to `maximum_height`. The finalized
/// chain anchor remains covered by the threshold signature; insertion into
/// this authoritative store is restricted to the consensus effect corridor,
/// which independently binds that anchor to the candidate's exact parent hash.
pub(crate) fn verified_latest_global_threshold_beacon_pulse_v1(
    world: &impl crate::state::WorldReadOnly,
    network_id: &NetworkId,
    maximum_height: u64,
) -> Result<FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconError> {
    let latest = world
        .global_beacon_latest_pulse()
        .get(&crate::state::GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY)
        .copied()
        .ok_or(GlobalThresholdBeaconError::InvalidPulseHistory)?;
    let pulse = world
        .global_beacon_pulses()
        .get(&latest.pulse_id)
        .copied()
        .ok_or(GlobalThresholdBeaconError::InvalidPulseHistory)?;
    if pulse.height > maximum_height
        || world
            .global_beacon_pulses()
            .iter()
            .any(|(_, candidate)| (candidate.height, candidate.round) > (pulse.height, pulse.round))
    {
        return Err(GlobalThresholdBeaconError::InvalidPulseHistory);
    }
    let pulse = verified_persisted_global_threshold_beacon_pulse_v1(world, network_id, pulse)?;
    if validate_persisted_global_threshold_beacon_pulse_v1(&pulse)? != latest {
        return Err(GlobalThresholdBeaconError::InvalidPulseHistory);
    }
    Ok(pulse)
}

/// Decode and verify one canonical Norito finalized-pulse envelope.
///
/// # Errors
///
/// Returns [`GlobalThresholdBeaconError`] when decoding, canonical re-encoding,
/// or pulse verification fails.
pub fn decode_finalized_global_threshold_beacon_pulse_v1(
    encoded: &[u8],
    session: &ValidatedGlobalThresholdBeaconSessionV1,
    expected_anchor: GlobalThresholdBeaconChainAnchorV1,
    expected_context: &GlobalThresholdBeaconPulseContextV1,
) -> Result<GlobalThresholdBeaconPulseLinkV1, GlobalThresholdBeaconError> {
    let pulse: FinalizedGlobalThresholdBeaconPulseV1 = norito::decode_from_bytes(encoded)
        .map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?;
    let canonical =
        norito::to_bytes(&pulse).map_err(|_| GlobalThresholdBeaconError::InvalidEncoding)?;
    if canonical != encoded {
        return Err(GlobalThresholdBeaconError::NonCanonicalEncoding);
    }
    verify_finalized_global_threshold_beacon_pulse_v1(
        session,
        &pulse,
        expected_anchor,
        expected_context,
    )
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(any(test, feature = "iroha-core-tests"))]
mod fixtures;
#[cfg(any(test, feature = "iroha-core-tests"))]
pub(crate) use fixtures::prepared_session_and_signers_fixture_for_keys_v1;
#[cfg(any(test, feature = "iroha-core-tests"))]
pub use fixtures::{
    complete_beacon_dkg_fixture_for_exact_session_v1, complete_beacon_dkg_fixture_for_seat_v1,
};
#[cfg(test)]
pub(crate) use fixtures::{
    prepared_session_and_signers_fixture_v1, signed_pulses_fixture_for_roster_and_anchors,
};
#[cfg(any(test, feature = "iroha-core-tests"))]
pub use fixtures::{pulse_context_fixture_v1, signed_persisted_pulse_fixture_for_world};

#[cfg(test)]
pub(crate) mod tests;
