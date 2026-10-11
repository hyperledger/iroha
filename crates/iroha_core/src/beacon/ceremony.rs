//! Signed all-edge DKG ceremony and install certificates for the global threshold beacon.
//!
//! The ceremony deals an exact `n = 3f + 1` seat roster with reconstruction
//! threshold `f + 1` through Core's signed all-edge DKG. Every seat is one
//! [`super::LocalGlobalThresholdBeaconDkgSeatV1`]: it owns only its own dealer
//! polynomial and hybrid recipient key, and signs its public frames with its
//! validator's BLS key. The ceremony relays public frames through the Core
//! reducer and never sees another seat's private contribution.
//!
//! 1. [`global_beacon_genesis_dkg_session_v1`] builds a fresh network's
//!    bootstrap session with the network's canonical genesis session and
//!    attempt identities and the nominal phase windows
//!    [`GLOBAL_BEACON_GENESIS_DKG_WINDOWS_V1`].
//! 2. [`GlobalBeaconCeremonyPlanV1`] validates a session, its ordered seat
//!    roster, and one production provider handle per seat.
//! 3. [`deal_global_beacon_at_logical_clock_v1`] runs every seat in one process
//!    only in explicit test fixtures. It returns one retained, finalized, not yet
//!    active public graph and one runtime credential per seat. Production seats prepare credential output through
//!    [`super::credential::PreparedGlobalBeaconCredentialV1`] before extracting
//!    their private share; the daemon retains failed export custody for retry.
//! 4. [`GlobalBeaconInstallContextV1`] drafts the `FinalizeGlobalBeaconKey`
//!    lifecycle certificate, signs its preimage for one effective height or a
//!    contiguous range of heights with a validator's own BLS key, and
//!    assembles exactly `2f + 1` signatures that Core's lifecycle verifier
//!    accepts.
//!
//! The finalized record binds heights only through the session's phase
//! windows and `finalized_at_height`, and Core accepts a bootstrap
//! finalization at any height at or after `finalized_at_height` inside the
//! genesis authorization. The nominal phase windows can therefore serve as a
//! logical clock for a deal made before the network starts. A failed ceremony
//! is never resumed: every seat is one-shot, and a new deal starts fresh seats.

#[cfg(any(test, feature = "iroha-core-tests"))]
use std::collections::BTreeSet;

use iroha_crypto::{Hash, Signature};
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::NetworkId;
use iroha_model_base::peer::PeerId;
use norito::{
    NoritoDeserialize, NoritoSerialize,
    derive::{JsonDeserialize, JsonSerialize},
};
use thiserror::Error;
#[cfg(any(test, feature = "iroha-core-tests"))]
use zeroize::Zeroizing;
#[cfg(any(test, feature = "iroha-core-tests"))]
use {
    iroha_data_model::consensus::GLOBAL_THRESHOLD_BEACON_VERSION_V1,
    iroha_data_model::consensus::GlobalThresholdBeaconDkgSessionV1,
    iroha_data_model::isi::consensus_keys::ThresholdKeyLifecycleActionV1,
    iroha_data_model::isi::consensus_keys::ThresholdKeyLifecycleCertificateV1,
    iroha_data_model::isi::consensus_keys::ThresholdKeyLifecycleSignatureV1,
};

use super::credential::ConsensusThresholdCredentialErrorV1;
use crate::state::ThresholdKeyLifecycleCertificateErrorV1;
#[cfg(any(test, feature = "iroha-core-tests"))]
use crate::state::{
    THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
    THRESHOLD_KEY_LIFECYCLE_PUBLIC_STATE_MAX_BYTES_V1,
    threshold_key_lifecycle_certificate_preimage_v1, verify_threshold_key_lifecycle_certificate_v1,
};
#[cfg(any(test, feature = "iroha-core-tests"))]
use {
    super::AdaptiveGlobalThresholdBeaconDkgCryptoV1, super::GlobalThresholdBeaconDkgStateV1,
    super::PreparedLocalGlobalThresholdBeaconDkgSeatV1,
    super::RetainedFinalizedGlobalThresholdBeaconSessionV1,
    super::credential::global_beacon_partial_signer_public_inventory_digest_v1,
    super::global_threshold_beacon_roster_hash_v1,
};
#[cfg(any(test, feature = "iroha-core-tests"))]
use {
    super::credential::encode_global_beacon_partial_signer_credential_v1,
    super::credential::global_beacon_partial_signer_inventory_digest_v1,
    super::credential::{
        PreparedGlobalBeaconCredentialV1, RuntimeGlobalBeaconShareProvisioningV1,
        SecretConsensusThresholdCredentialV1,
    },
};

#[cfg(any(test, feature = "iroha-core-tests"))]
/// Maximum number of effective heights one install-range signing call covers.
pub const GLOBAL_BEACON_INSTALL_RANGE_MAX_HEIGHTS_V1: u16 = 64;

#[cfg(any(test, feature = "iroha-core-tests"))]
/// Nominal genesis phase windows: start, commitments end, deliveries end and
/// acceptances end. The transcript finalizes at the last one.
pub const GLOBAL_BEACON_GENESIS_DKG_WINDOWS_V1: [u64; 4] = [1, 2, 3, 4];

/// Closed failures of the beacon ceremony.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GlobalBeaconCeremonyErrorV1 {
    /// An original public-session admission or construction owner refused local work.
    #[error(transparent)]
    Session(#[from] super::GlobalThresholdBeaconSessionError),
    /// An original local seat producer or its prepared backing failed.
    #[error(transparent)]
    LocalDkg(#[from] super::LocalGlobalThresholdBeaconDkgErrorV1),
    /// The public session, roster, provider bindings, or record was invalid.
    #[error("global-beacon ceremony public input is invalid")]
    InvalidPlan,
    /// A seat signer is missing or does not own its roster seat.
    #[error("global-beacon seat signers do not match the ordered roster")]
    SeatSigner,
    /// A height was outside the required install window.
    #[error("global-beacon ceremony height is outside its install window")]
    Height,
    /// Seat DKG, reducer admission or transcript validation failed.
    #[error("global-beacon ceremony cryptographic validation failed")]
    Crypto,
    /// A seat credential could not be produced.
    #[error(transparent)]
    Credential(#[from] ConsensusThresholdCredentialErrorV1),
    /// Exact original prepared output or share-import producer failure.
    #[error(transparent)]
    CredentialOutput(#[from] super::credential::GlobalBeaconCredentialEncodeErrorV1),
    /// The signing key does not own a seat in the authorization roster.
    #[error("signing key is not a member of the install authorization roster")]
    NotAuthorized,
    /// An install range was malformed, foreign, or did not cover the height.
    #[error("global-beacon install signature range is invalid")]
    InvalidRange,
    /// The supplied signers do not form exactly one `2f + 1` quorum.
    #[error("install signatures do not form an exact 2f + 1 quorum")]
    Quorum,
    /// Core's lifecycle-certificate verifier rejected the assembled certificate.
    #[error(transparent)]
    Certificate(#[from] ThresholdKeyLifecycleCertificateErrorV1),
}

/// Canonical bootstrap beacon session identity of a network.
///
/// A network has exactly one genesis transcript identity, so a bootstrap
/// session can never be rerolled under the same signed genesis.
#[must_use]
pub fn global_beacon_genesis_session_id_v1(network_id: NetworkId) -> [u8; 32] {
    Hash::new_from_chunks(&[
        b"iroha.global-beacon.genesis-session.v1\0",
        network_id.as_bytes(),
    ])
    .into()
}

/// Canonical bootstrap DKG attempt identity of a network.
#[must_use]
pub fn global_beacon_genesis_attempt_id_v1(network_id: NetworkId) -> [u8; 32] {
    Hash::new_from_chunks(&[
        b"iroha.global-beacon.genesis-attempt.v1\0",
        network_id.as_bytes(),
    ])
    .into()
}

#[cfg(any(test, feature = "iroha-core-tests"))]
/// Build the bootstrap DKG session of an exact `3f + 1` genesis roster.
///
/// The session has threshold `f + 1`, authority generation 0, the network's
/// canonical genesis session and attempt identities, and the nominal phase
/// windows [`GLOBAL_BEACON_GENESIS_DKG_WINDOWS_V1`].
///
/// # Errors
///
/// Returns [`GlobalBeaconCeremonyErrorV1::InvalidPlan`] when the roster is not
/// a unique `3f + 1` committee of at least four seats supported by the
/// threshold scheme.
pub fn global_beacon_genesis_dkg_session_v1(
    network_id: NetworkId,
    roster: &[PeerId],
) -> Result<GlobalThresholdBeaconDkgSessionV1, GlobalBeaconCeremonyErrorV1> {
    let committee_size = exact_committee_size(roster)?;
    let [
        start_height,
        commitments_end_height,
        deliveries_end_height,
        acceptances_end_height,
    ] = GLOBAL_BEACON_GENESIS_DKG_WINDOWS_V1;
    let session = GlobalThresholdBeaconDkgSessionV1 {
        version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
        network_id,
        session_id: global_beacon_genesis_session_id_v1(network_id),
        attempt_id: global_beacon_genesis_attempt_id_v1(network_id),
        authority_generation: 0,
        roster_hash: global_threshold_beacon_roster_hash_v1(roster),
        committee_size,
        threshold: (committee_size - 1) / 3 + 1,
        start_height,
        commitments_end_height,
        deliveries_end_height,
        acceptances_end_height,
    };
    GlobalThresholdBeaconDkgStateV1::validate_session(
        &session,
        &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
    )
    .map_err(|_| GlobalBeaconCeremonyErrorV1::InvalidPlan)?;
    Ok(session)
}

#[cfg(any(test, feature = "iroha-core-tests"))]
/// Validated public inputs of one beacon deal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalBeaconCeremonyPlanV1 {
    dkg_session: GlobalThresholdBeaconDkgSessionV1,
    roster: Vec<PeerId>,
    provider_handles: Vec<String>,
    provider_revision: u64,
}

#[cfg(any(test, feature = "iroha-core-tests"))]
impl GlobalBeaconCeremonyPlanV1 {
    /// Validate one deal plan.
    ///
    /// Seat `i` (one-based) is `roster[i - 1]` and is bound to
    /// `provider_handles[i - 1]` at `provider_revision`.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::InvalidPlan`] unless the roster is
    /// a unique `3f + 1` committee, the session names exactly that roster with
    /// committee `n` and threshold `f + 1`, the phase schedule is valid, the
    /// provider revision is nonzero, and there is one distinct production
    /// handle per seat.
    pub fn new(
        dkg_session: GlobalThresholdBeaconDkgSessionV1,
        roster: Vec<PeerId>,
        provider_handles: Vec<String>,
        provider_revision: u64,
    ) -> Result<Self, GlobalBeaconCeremonyErrorV1> {
        let committee_size = exact_committee_size(&roster)?;
        if dkg_session.committee_size != committee_size
            || dkg_session.threshold != (committee_size - 1) / 3 + 1
            || dkg_session.roster_hash != global_threshold_beacon_roster_hash_v1(&roster)
            || provider_revision == 0
            || provider_handles.len() != roster.len()
            || provider_handles.iter().collect::<BTreeSet<_>>().len() != roster.len()
            || provider_handles.iter().any(|handle| {
                iroha_config::parameters::validate_production_runtime_handle(handle).is_err()
            })
        {
            return Err(GlobalBeaconCeremonyErrorV1::InvalidPlan);
        }
        GlobalThresholdBeaconDkgStateV1::validate_session(
            &dkg_session,
            &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
        )
        .map_err(|_| GlobalBeaconCeremonyErrorV1::InvalidPlan)?;
        Ok(Self {
            dkg_session,
            roster,
            provider_handles,
            provider_revision,
        })
    }

    /// Borrow the immutable DKG session.
    #[must_use]
    pub const fn dkg_session(&self) -> &GlobalThresholdBeaconDkgSessionV1 {
        &self.dkg_session
    }

    /// Borrow the ordered seat roster.
    #[must_use]
    pub fn roster(&self) -> &[PeerId] {
        &self.roster
    }

    /// Borrow the per-seat production provider handles.
    #[must_use]
    pub fn provider_handles(&self) -> &[String] {
        &self.provider_handles
    }

    /// Return the public provider-catalog revision bound into every seat.
    #[must_use]
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Encode a test fixture seat's runtime credential from its aggregated private share.
    ///
    /// `components` is this seat's diagnostic aggregate from the same
    /// side-effect-free arithmetic used by the production checkpoint. The
    /// credential codec verifies its exact public equation before writing the
    /// prepared secret frame. This fixture grants no native extraction authority.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::InvalidPlan`] for a transcript of
    /// another session or a seat outside the roster, and
    /// [`GlobalBeaconCeremonyErrorV1::CredentialOutput`] when the share does not
    /// match its public transcript and seat.
    pub fn seat_credential(
        &self,
        public: super::ValidatedGlobalThresholdBeaconSessionV1,
        signer_index: u16,
        components: Zeroizing<[[u8; 32]; 3]>,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<GlobalBeaconSeatCredentialV1, GlobalBeaconCeremonyErrorV1> {
        let offset = usize::from(signer_index)
            .checked_sub(1)
            .filter(|offset| *offset < self.roster.len())
            .ok_or(GlobalBeaconCeremonyErrorV1::InvalidPlan)?;
        if public.adaptive_dkg.session != self.dkg_session {
            return Err(GlobalBeaconCeremonyErrorV1::InvalidPlan);
        }
        let network_id = public.network_id;
        let inventory = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            public,
            signer_index,
            components,
        )];
        let policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &inventory)?;
        let handle = self.provider_handles[offset].clone();
        let mut prepared = PreparedGlobalBeaconCredentialV1::new(
            network_id,
            &handle,
            self.provider_revision,
            policy_digest,
            inventory
                .iter()
                .map(|share| (share.authenticated_session(), share.signer_index())),
            budget,
        )?;
        encode_global_beacon_partial_signer_credential_v1(
            &mut prepared,
            inventory
                .iter()
                .map(RuntimeGlobalBeaconShareProvisioningV1::credential_source),
        )?;
        let credential = prepared.into_credential().map_err(|(_, error)| error)?;
        Ok(GlobalBeaconSeatCredentialV1 {
            binding: GlobalBeaconSeatBindingV1 {
                signer_index,
                validator: self.roster[offset].clone(),
                handle,
                revision: self.provider_revision,
                policy_digest,
            },
            credential,
        })
    }

    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Verify a finalized record and its public seat bindings against this plan.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::InvalidPlan`] when the record is
    /// invalid or not finalized from this plan's session, or when any seat
    /// binding differs in order, validator, handle, revision or inventory digest.
    pub fn verify_seat_bindings(
        &self,
        record: &RetainedFinalizedGlobalThresholdBeaconSessionV1,
        bindings: &[GlobalBeaconSeatBindingV1],
    ) -> Result<(), GlobalBeaconCeremonyErrorV1> {
        record
            .validate()
            .map_err(|_| GlobalBeaconCeremonyErrorV1::InvalidPlan)?;
        if record.session.adaptive_dkg.session != self.dkg_session
            || bindings.len() != self.roster.len()
        {
            return Err(GlobalBeaconCeremonyErrorV1::InvalidPlan);
        }
        for (offset, binding) in bindings.iter().enumerate() {
            let signer_index = seat_index(offset)?;
            let policy_digest = global_beacon_partial_signer_public_inventory_digest_v1(
                record.session.network_id,
                &[(&record.session, signer_index)],
            )?;
            if binding.signer_index != signer_index
                || binding.validator != self.roster[offset]
                || binding.handle != self.provider_handles[offset]
                || binding.revision != self.provider_revision
                || binding.policy_digest != policy_digest
            {
                return Err(GlobalBeaconCeremonyErrorV1::InvalidPlan);
            }
        }
        Ok(())
    }
}

/// Public runtime-provider binding of one dealt seat.
///
/// Node configuration renders these values as the global-beacon partial-signer
/// provider handle, revision and policy digest; the seat credential header
/// carries the same values.
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
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_core::beacon::ceremony::GlobalBeaconSeatBindingV1")]
pub struct GlobalBeaconSeatBindingV1 {
    /// One-based DKG signer seat.
    pub signer_index: u16,
    /// Validator owning this seat.
    pub validator: PeerId,
    /// Production runtime-provider handle.
    pub handle: String,
    /// Public provider-catalog revision.
    pub revision: u64,
    /// Public session-and-seat inventory digest (the provider policy digest).
    pub policy_digest: [u8; 32],
}

#[cfg(any(test, feature = "iroha-core-tests"))]
/// One dealt seat: its public binding and its zeroizing runtime credential.
pub struct GlobalBeaconSeatCredentialV1 {
    /// Public provider binding rendered into the seat's node configuration.
    pub binding: GlobalBeaconSeatBindingV1,
    /// Canonical runtime credential for the seat's supervisor; never persisted by Core.
    pub credential: SecretConsensusThresholdCredentialV1,
}

#[cfg(any(test, feature = "iroha-core-tests"))]
/// Result of a completed deal: one finalized, not yet active record and every seat.
pub struct DealtGlobalBeaconV1 {
    /// Finalized public key-session owner, shared unchanged with the install context.
    pub record: RetainedFinalizedGlobalThresholdBeaconSessionV1,
    /// Seat credentials in one-based seat order.
    pub seats: Vec<GlobalBeaconSeatCredentialV1>,
}

#[cfg(any(test, feature = "iroha-core-tests"))]
/// Run every seat of `plan` in process against the session's nominal phase windows.
///
/// `signers[i]` is the validator key of seat `i + 1`. Each seat publishes its
/// signed recipient key and dealer commitment at `start_height`, delivers its
/// signed encrypted edges at `commitments_end_height`, accepts its inbound
/// edges at `deliveries_end_height`, and the transcript finalizes at
/// `acceptances_end_height`. This test-only logical-clock fixture retires every
/// dealer polynomial after all original edges enter the public reducer; every
/// seat aggregates only its own accepted contributions. Filesystem durability
/// and daemon restart qualification are separate requirements.
///
/// # Errors
///
/// Returns [`GlobalBeaconCeremonyErrorV1::SeatSigner`] unless there is exactly
/// one signer per seat owning that seat, [`GlobalBeaconCeremonyErrorV1::Crypto`]
/// when a seat, the reducer or transcript validation rejects a frame, and
/// [`GlobalBeaconCeremonyErrorV1::CredentialOutput`] when a seat credential fails.
pub fn deal_global_beacon_at_logical_clock_v1(
    plan: &GlobalBeaconCeremonyPlanV1,
    signers: &[&KeyPair],
    budget: &iroha_allocation::AllocationBudget,
) -> Result<DealtGlobalBeaconV1, GlobalBeaconCeremonyErrorV1> {
    let session = plan.dkg_session;
    if signers.len() != plan.roster.len()
        || signers
            .iter()
            .zip(&plan.roster)
            .any(|(signer, peer)| signer.public_key() != peer.public_key())
    {
        return Err(GlobalBeaconCeremonyErrorV1::SeatSigner);
    }
    let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
    // Complete every seat's original admission before any private randomness.
    let prepared_seats = signers
        .iter()
        .enumerate()
        .map(|(offset, signer)| {
            PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
                session,
                &plan.roster,
                seat_index(offset)?,
                signer,
                budget,
            )
            .map_err(GlobalBeaconCeremonyErrorV1::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let verifier = prepared_seats
        .first()
        .ok_or(GlobalBeaconCeremonyErrorV1::SeatSigner)?
        .prepare_final_session_verifier()?;
    let mut seats = prepared_seats
        .into_iter()
        .zip(signers)
        .map(|(prepared, signer)| {
            prepared
                .generate(signer)
                .map_err(GlobalBeaconCeremonyErrorV1::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut public = GlobalThresholdBeaconDkgStateV1::new(session, &crypto, budget)?;
    let (recipient_keys, dealer_commitments): (Vec<_>, Vec<_>) = seats
        .iter()
        .map(|seat| {
            let (key, commitment) = seat.publication();
            (key.clone(), commitment.clone())
        })
        .unzip();
    for key in &recipient_keys {
        public.record_recipient_key(session.start_height, key)?;
    }
    for commitment in &dealer_commitments {
        public.record_dealer_commitment(session.start_height, commitment, &crypto)?;
    }
    let delivery_height = session.commitments_end_height;
    for (seat, signer) in seats.iter_mut().zip(signers) {
        for edge in seat.deliver(
            &recipient_keys,
            &dealer_commitments,
            delivery_height,
            signer,
        )? {
            public.record_encrypted_share(delivery_height, edge)?;
        }
    }
    // This fixture mirrors the complete public publication boundary. It does
    // not establish the production publisher's file/directory durability.
    for seat in &mut seats {
        seat.retire_durably_published_dealer()?;
    }
    let delivered = public.public_snapshot()?;
    let accepted_height = session.deliveries_end_height;
    for (seat, signer) in seats.iter_mut().zip(signers) {
        for acceptance in seat.accept(&delivered, accepted_height, signer)? {
            public.record_share_acceptance(accepted_height, acceptance)?;
        }
    }
    // The accepted snapshot has served every seat. Retire that complete graph
    // before the reducer constructs its final projection in the same finite pool.
    drop(delivered);
    public.finalize(session.acceptances_end_height, &crypto)?;
    let finalized = public.into_finalized()?;
    let binding = super::GlobalThresholdBeaconSessionBindingV1 {
        network_id: finalized.network_id,
        session_id: finalized.session_id,
        roster_hash: finalized.roster_hash,
        transcript_hash: finalized.transcript_hash,
    };
    // Preserve the reducer's exact original graph and ledger. Verification uses
    // the workspace and shared shell prepared before the first private attempt.
    let sealed = verifier.seal(finalized.owner, &binding).map_err(
        |(_verifier, _source, error)| match error {
            super::GlobalThresholdBeaconSessionError::Invalid(_) => {
                GlobalBeaconCeremonyErrorV1::Crypto
            }
            original => GlobalBeaconCeremonyErrorV1::Session(original),
        },
    )?;
    let mut credentials = Vec::with_capacity(seats.len());
    for seat in seats {
        let components = seat
            .aggregate_private_share(&sealed)?
            .into_components_for_runtime_custody();
        credentials.push(plan.seat_credential(
            sealed.clone(),
            seat.seat_index(),
            components,
            budget,
        )?);
    }
    // Every private seat owner has retired. The outgoing lifecycle and install
    // context continue sharing the sole authenticated original public graph.
    let record = RetainedFinalizedGlobalThresholdBeaconSessionV1 {
        session: sealed,
        activated_at_height: None,
        retired_at_height: None,
    };
    Ok(DealtGlobalBeaconV1 {
        record,
        seats: credentials,
    })
}

/// Lifecycle-certificate preimage signatures by one host for consecutive effective heights.
///
/// `signatures[i]` authorizes the install certificate whose effective height
/// is `first_effective_height + i`.
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
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_core::beacon::ceremony::GlobalBeaconInstallRangeSignaturesV1")]
pub struct GlobalBeaconInstallRangeSignaturesV1 {
    /// Key session the signatures install.
    pub session_id: [u8; 32],
    /// Zero-based seat in the ordered authorization roster.
    pub signer_index: u16,
    /// Effective height authorized by the first signature.
    pub first_effective_height: u64,
    /// One signature per consecutive effective height.
    pub signatures: Vec<Signature>,
}

#[cfg(any(test, feature = "iroha-core-tests"))]
/// Public install context shared by every host signer and the controller assembler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalBeaconInstallContextV1 {
    record: RetainedFinalizedGlobalThresholdBeaconSessionV1,
    authorization_roster: Vec<PeerId>,
    public_state: Vec<u8>,
    quorum: u16,
}

#[cfg(any(test, feature = "iroha-core-tests"))]
impl GlobalBeaconInstallContextV1 {
    /// Bind a finalized, inactive record to the exact ordered authorization roster.
    ///
    /// The authorization roster is the validator roster at the install
    /// height; on a fresh network it equals the DKG seat roster.
    ///
    /// TODO: accept an expected active predecessor for rotation finalizations;
    /// this bootstrap context always signs `expected_active_session_id = None`.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::InvalidPlan`] for an invalid,
    /// active or retired record, an oversized public state, or a roster that is
    /// empty, duplicated, or not `3f + 1`.
    pub fn new(
        record: RetainedFinalizedGlobalThresholdBeaconSessionV1,
        authorization_roster: Vec<PeerId>,
    ) -> Result<Self, GlobalBeaconCeremonyErrorV1> {
        record
            .validate()
            .map_err(|_| GlobalBeaconCeremonyErrorV1::InvalidPlan)?;
        let committee_size = u16::try_from(authorization_roster.len())
            .map_err(|_| GlobalBeaconCeremonyErrorV1::InvalidPlan)?;
        if record.activated_at_height.is_some()
            || record.retired_at_height.is_some()
            || committee_size == 0
            || (committee_size - 1) % 3 != 0
            || authorization_roster.iter().collect::<BTreeSet<_>>().len()
                != authorization_roster.len()
        {
            return Err(GlobalBeaconCeremonyErrorV1::InvalidPlan);
        }
        let public_state = norito::encode_canonical(&record)
            .map_err(|_| GlobalBeaconCeremonyErrorV1::InvalidPlan)?;
        if public_state.is_empty()
            || public_state.len() > THRESHOLD_KEY_LIFECYCLE_PUBLIC_STATE_MAX_BYTES_V1
        {
            return Err(GlobalBeaconCeremonyErrorV1::InvalidPlan);
        }
        Ok(Self {
            record,
            authorization_roster,
            public_state,
            quorum: (committee_size - 1) / 3 * 2 + 1,
        })
    }

    /// Borrow the finalized record being installed.
    #[must_use]
    pub const fn record(&self) -> &RetainedFinalizedGlobalThresholdBeaconSessionV1 {
        &self.record
    }

    /// Borrow the ordered authorization roster.
    #[must_use]
    pub fn authorization_roster(&self) -> &[PeerId] {
        &self.authorization_roster
    }

    /// Return the exact `2f + 1` signature count required by the certificate.
    #[must_use]
    pub const fn quorum(&self) -> u16 {
        self.quorum
    }

    /// Draft the unsigned install certificate for one effective height.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::Height`] unless `effective_height`
    /// is strictly after the record's `finalized_at_height`.
    pub fn draft_certificate(
        &self,
        effective_height: u64,
    ) -> Result<ThresholdKeyLifecycleCertificateV1, GlobalBeaconCeremonyErrorV1> {
        if effective_height <= self.record.session.adaptive_dkg.finalized_at_height {
            return Err(GlobalBeaconCeremonyErrorV1::Height);
        }
        let committee_size = u16::try_from(self.authorization_roster.len())
            .map_err(|_| GlobalBeaconCeremonyErrorV1::InvalidPlan)?;
        Ok(ThresholdKeyLifecycleCertificateV1 {
            version: THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
            action: ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
            expected_active_session_id: None,
            effective_height,
            network_id: self.record.session.network_id,
            roster_hash: global_threshold_beacon_roster_hash_v1(&self.authorization_roster),
            committee_size,
            quorum: self.quorum,
            session_id: self.record.session.session_id,
            transcript_hash: self.record.session.transcript_hash,
            public_state: self.public_state.clone(),
            signatures: Vec::new(),
        })
    }

    /// Return the zero-based authorization seat owned by `public_key`.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::NotAuthorized`] when the key is
    /// not in the authorization roster.
    pub fn signer_index(&self, public_key: &PublicKey) -> Result<u16, GlobalBeaconCeremonyErrorV1> {
        self.authorization_roster
            .iter()
            .position(|peer| peer.public_key() == public_key)
            .and_then(|index| u16::try_from(index).ok())
            .ok_or(GlobalBeaconCeremonyErrorV1::NotAuthorized)
    }

    /// Sign the install-certificate preimage for one effective height.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::NotAuthorized`] for a key outside
    /// the authorization roster, [`GlobalBeaconCeremonyErrorV1::Height`] for a
    /// height not after finalization, and
    /// [`GlobalBeaconCeremonyErrorV1::Crypto`] if signing fails.
    pub fn sign(
        &self,
        key: &KeyPair,
        effective_height: u64,
    ) -> Result<ThresholdKeyLifecycleSignatureV1, GlobalBeaconCeremonyErrorV1> {
        let signer_index = self.signer_index(key.public_key())?;
        let preimage = threshold_key_lifecycle_certificate_preimage_v1(
            &self.draft_certificate(effective_height)?,
        )?;
        let signature = Signature::try_new(key.private_key(), &preimage)
            .map_err(|_| GlobalBeaconCeremonyErrorV1::Crypto)?;
        signature
            .verify(key.public_key(), &preimage)
            .map_err(|_| GlobalBeaconCeremonyErrorV1::Crypto)?;
        Ok(ThresholdKeyLifecycleSignatureV1 {
            signer_index,
            signature,
        })
    }

    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Sign install-certificate preimages for `count` consecutive effective heights.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::InvalidRange`] for a zero or
    /// excessive count or a height overflow, and otherwise the failures of
    /// [`Self::sign`].
    pub fn sign_range(
        &self,
        key: &KeyPair,
        first_effective_height: u64,
        count: u16,
    ) -> Result<GlobalBeaconInstallRangeSignaturesV1, GlobalBeaconCeremonyErrorV1> {
        if count == 0 || count > GLOBAL_BEACON_INSTALL_RANGE_MAX_HEIGHTS_V1 {
            return Err(GlobalBeaconCeremonyErrorV1::InvalidRange);
        }
        first_effective_height
            .checked_add(u64::from(count) - 1)
            .ok_or(GlobalBeaconCeremonyErrorV1::InvalidRange)?;
        let mut signer_index = None;
        let mut signatures = Vec::with_capacity(usize::from(count));
        for offset in 0..u64::from(count) {
            let signed = self.sign(key, first_effective_height + offset)?;
            signer_index = Some(signed.signer_index);
            signatures.push(signed.signature);
        }
        Ok(GlobalBeaconInstallRangeSignaturesV1 {
            session_id: self.record.session.session_id,
            signer_index: signer_index.ok_or(GlobalBeaconCeremonyErrorV1::InvalidRange)?,
            first_effective_height,
            signatures,
        })
    }

    /// Assemble the certificate from signatures in their exact certificate order.
    ///
    /// Core's lifecycle verifier is authoritative: it requires exactly `2f + 1`
    /// strictly increasing signer seats and valid signatures at
    /// `effective_height`.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::Certificate`] for reordered,
    /// duplicate, missing, extra or invalid signatures, and the drafting
    /// failures of [`Self::draft_certificate`].
    pub fn assemble(
        &self,
        effective_height: u64,
        signatures: Vec<ThresholdKeyLifecycleSignatureV1>,
    ) -> Result<ThresholdKeyLifecycleCertificateV1, GlobalBeaconCeremonyErrorV1> {
        let mut certificate = self.draft_certificate(effective_height)?;
        certificate.signatures = signatures;
        verify_threshold_key_lifecycle_certificate_v1(
            &certificate,
            &self.record.session.network_id,
            effective_height,
            &self.authorization_roster,
        )?;
        Ok(certificate)
    }

    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Assemble the certificate for `effective_height` from exactly `2f + 1` hosts' ranges.
    ///
    /// Range order is irrelevant: the selected signatures are placed in
    /// canonical seat order before Core verification.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalBeaconCeremonyErrorV1::Quorum`] unless exactly `2f + 1`
    /// distinct seats are supplied,
    /// [`GlobalBeaconCeremonyErrorV1::InvalidRange`] for a foreign, oversized
    /// or non-covering range, and the failures of [`Self::assemble`].
    pub fn assemble_from_ranges(
        &self,
        effective_height: u64,
        ranges: &[GlobalBeaconInstallRangeSignaturesV1],
    ) -> Result<ThresholdKeyLifecycleCertificateV1, GlobalBeaconCeremonyErrorV1> {
        if ranges.len() != usize::from(self.quorum) {
            return Err(GlobalBeaconCeremonyErrorV1::Quorum);
        }
        let mut signatures = Vec::with_capacity(ranges.len());
        for range in ranges {
            if range.session_id != self.record.session.session_id
                || range.signatures.is_empty()
                || range.signatures.len() > usize::from(GLOBAL_BEACON_INSTALL_RANGE_MAX_HEIGHTS_V1)
            {
                return Err(GlobalBeaconCeremonyErrorV1::InvalidRange);
            }
            let signature = effective_height
                .checked_sub(range.first_effective_height)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| range.signatures.get(offset))
                .ok_or(GlobalBeaconCeremonyErrorV1::InvalidRange)?;
            signatures.push(ThresholdKeyLifecycleSignatureV1 {
                signer_index: range.signer_index,
                signature: signature.clone(),
            });
        }
        signatures.sort_by_key(|signed| signed.signer_index);
        if signatures
            .windows(2)
            .any(|pair| pair[0].signer_index == pair[1].signer_index)
        {
            return Err(GlobalBeaconCeremonyErrorV1::Quorum);
        }
        self.assemble(effective_height, signatures)
    }
}

#[cfg(any(test, feature = "iroha-core-tests"))]
fn exact_committee_size(roster: &[PeerId]) -> Result<u16, GlobalBeaconCeremonyErrorV1> {
    let committee_size =
        u16::try_from(roster.len()).map_err(|_| GlobalBeaconCeremonyErrorV1::InvalidPlan)?;
    if committee_size < 4
        || (committee_size - 1) % 3 != 0
        || roster.iter().collect::<BTreeSet<_>>().len() != roster.len()
    {
        return Err(GlobalBeaconCeremonyErrorV1::InvalidPlan);
    }
    Ok(committee_size)
}

#[cfg(any(test, feature = "iroha-core-tests"))]
fn seat_index(offset: usize) -> Result<u16, GlobalBeaconCeremonyErrorV1> {
    offset
        .checked_add(1)
        .and_then(|index| u16::try_from(index).ok())
        .ok_or(GlobalBeaconCeremonyErrorV1::InvalidPlan)
}

#[cfg(test)]
#[path = "ceremony_tests.rs"]
mod tests;
