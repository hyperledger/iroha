//! Feature-isolated threshold-beacon signer for genuine Parliament network tests.
//!
//! This module is compiled only into the dedicated test daemon. It derives one
//! deterministic, proof-valid adaptive-DKG share for the exact local seat in an
//! exact four-validator roster. Two domain-separated public fixtures exercise
//! initial installation and one genuine key rotation. The signer never emits
//! pulses, final signatures, seeds, reducer state, or validation results; the
//! ordinary Sumeragi aggregator still independently verifies every returned
//! share and constructs the unique pulse.

#[cfg(not(debug_assertions))]
compile_error!(
    "the feature-isolated Parliament beacon fixture signer cannot be compiled into optimized code"
);

use super::{
    AdaptiveGlobalThresholdBeaconDkgCryptoV1, FinalizedGlobalThresholdBeaconKeySessionRecordV1,
    GlobalThresholdBeaconDkgStateV1, GlobalThresholdBeaconPartialSignerV1,
    GlobalThresholdBeaconSessionBindingV1, InMemoryGlobalThresholdBeaconPartialSignerV1,
    ValidatedGlobalThresholdBeaconSessionV1, adaptive_beacon_parameters,
    global_threshold_beacon_roster_hash_v1, validate_global_threshold_beacon_session_v1,
};
use iroha_allocation::AllocationBudget;
use iroha_crypto::{
    Hash,
    threshold_bls::{
        AdaptiveThresholdBlsParameters, AdaptiveThresholdBlsSecretShare, BeaconPurpose,
        DasRenDealerSecret, ValidatedDealerCommitment,
    },
};
use iroha_data_model::{
    NetworkId,
    consensus::{
        GLOBAL_THRESHOLD_BEACON_VERSION_V1, GlobalThresholdBeaconDkgConstantProofV1,
        GlobalThresholdBeaconDkgDealerCommitmentV1, GlobalThresholdBeaconDkgSessionV1,
        GlobalThresholdBeaconPartialSignatureV1,
    },
};
use iroha_model_base::peer::PeerId;
use rand::{SeedableRng as _, rngs::StdRng};
use thiserror::Error;

const EXACT_TEST_VALIDATORS_V1: usize = 4;
const EXACT_TEST_THRESHOLD_V1: u16 = 2;
const TEST_SESSION_ID_DOMAIN_V1: &[u8] = b"iroha.test-network.parliament-beacon.session.v1\0";
const TEST_SUCCESSOR_SESSION_ID_DOMAIN_V1: &[u8] =
    b"iroha.test-network.parliament-beacon.successor-session.v1\0";
const TEST_DEALER_SEED_DOMAIN_V1: &[u8] = b"iroha.test-network.parliament-beacon.dealers.v1\0";

/// Closed construction failure for the feature-isolated Parliament beacon fixture.
#[derive(Debug, Error)]
pub enum TestNetworkParliamentBeaconSignerErrorV1 {
    /// The fixture is intentionally limited to the exact four-validator corridor.
    #[error("test Parliament beacon requires exactly four distinct validators")]
    InvalidRoster,
    /// The configured local peer does not occupy exactly one frozen roster seat.
    #[error("local test Parliament beacon seat is not exact")]
    InvalidLocalSeat,
    /// The deterministic adaptive-DKG transcript or derived share was rejected.
    #[error("test Parliament beacon cryptographic fixture is invalid")]
    InvalidCryptographicFixture,
    /// The caller's original session admission or canonical validation failed.
    #[error(transparent)]
    Session(#[from] super::GlobalThresholdBeaconSessionError),
}

struct DeterministicFixtureV1 {
    session: ValidatedGlobalThresholdBeaconSessionV1,
    parameters: AdaptiveThresholdBlsParameters<BeaconPurpose>,
    dealer_secrets: Vec<DasRenDealerSecret<BeaconPurpose>>,
    dealer_commitments: Vec<ValidatedDealerCommitment<BeaconPurpose>>,
}

fn validate_roster_v1(roster: &[PeerId]) -> Result<(), TestNetworkParliamentBeaconSignerErrorV1> {
    if roster.len() != EXACT_TEST_VALIDATORS_V1
        || roster
            .iter()
            .enumerate()
            .any(|(index, peer)| roster[index + 1..].contains(peer))
    {
        return Err(TestNetworkParliamentBeaconSignerErrorV1::InvalidRoster);
    }
    Ok(())
}

fn deterministic_session_v1(
    network_id: NetworkId,
    roster: &[PeerId],
    successor: bool,
) -> Result<GlobalThresholdBeaconDkgSessionV1, TestNetworkParliamentBeaconSignerErrorV1> {
    validate_roster_v1(roster)?;
    let roster_hash = global_threshold_beacon_roster_hash_v1(roster);
    let session_domain = if successor {
        TEST_SUCCESSOR_SESSION_ID_DOMAIN_V1
    } else {
        TEST_SESSION_ID_DOMAIN_V1
    };
    let mut session_id: [u8; 32] =
        Hash::new_from_chunks(&[session_domain, network_id.as_bytes(), &roster_hash]).into();
    if session_id == [0; 32] {
        session_id[0] = 1;
    }
    Ok(GlobalThresholdBeaconDkgSessionV1 {
        version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
        network_id,
        session_id,
        attempt_id: session_id,
        authority_generation: 0,
        roster_hash,
        committee_size: u16::try_from(EXACT_TEST_VALIDATORS_V1).expect("fixture value fits u16"),
        threshold: EXACT_TEST_THRESHOLD_V1,
        start_height: 1,
        commitments_end_height: 2,
        deliveries_end_height: 3,
        acceptances_end_height: 4,
    })
}

fn dealer_commitment_dto_v1(
    dealer: &ValidatedDealerCommitment<BeaconPurpose>,
) -> GlobalThresholdBeaconDkgDealerCommitmentV1 {
    GlobalThresholdBeaconDkgDealerCommitmentV1 {
        dealer_index: dealer.dealer_index(),
        coefficient_commitments: dealer
            .coefficients()
            .iter()
            .map(|coefficient| *coefficient.as_bytes())
            .collect(),
        constant_term_proof: GlobalThresholdBeaconDkgConstantProofV1 {
            commitment: *dealer.constant_proof().commitment_bytes(),
            response: *dealer.constant_proof().response_bytes(),
        },
        signature: iroha_crypto::Signature::from_bytes(&[]),
    }
}

fn deterministic_fixture_v1(
    network_id: NetworkId,
    roster: &[PeerId],
    successor: bool,
    budget: &AllocationBudget,
) -> Result<DeterministicFixtureV1, TestNetworkParliamentBeaconSignerErrorV1> {
    let dkg_session = deterministic_session_v1(network_id, roster, successor)?;
    let parameters = adaptive_beacon_parameters(&dkg_session)
        .map_err(|_| TestNetworkParliamentBeaconSignerErrorV1::InvalidCryptographicFixture)?;
    let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
    let mut state = GlobalThresholdBeaconDkgStateV1::new(dkg_session, &crypto, budget)
        .map_err(|_| TestNetworkParliamentBeaconSignerErrorV1::InvalidCryptographicFixture)?;
    let dealer_seed: [u8; 32] = Hash::new_from_chunks(&[
        TEST_DEALER_SEED_DOMAIN_V1,
        dkg_session.network_id.as_bytes(),
        &dkg_session.session_id,
        &dkg_session.roster_hash,
    ])
    .into();
    let mut rng = StdRng::from_seed(dealer_seed);
    let mut dealer_secrets = Vec::with_capacity(EXACT_TEST_VALIDATORS_V1);
    let mut dealer_commitments = Vec::with_capacity(EXACT_TEST_VALIDATORS_V1);
    for dealer_index in 1_u16..=dkg_session.committee_size {
        let (secret, commitment) =
            DasRenDealerSecret::generate_with_rng(&parameters, dealer_index, &mut rng).map_err(
                |_| TestNetworkParliamentBeaconSignerErrorV1::InvalidCryptographicFixture,
            )?;
        state
            .record_dealer_commitment(1, &dealer_commitment_dto_v1(&commitment), &crypto)
            .map_err(|_| TestNetworkParliamentBeaconSignerErrorV1::InvalidCryptographicFixture)?;
        dealer_secrets.push(secret);
        dealer_commitments.push(commitment);
    }
    let record = state
        .finalize(dkg_session.acceptances_end_height, &crypto)
        .map_err(|_| TestNetworkParliamentBeaconSignerErrorV1::InvalidCryptographicFixture)?
        .clone();
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: record.network_id,
        session_id: record.session_id,
        roster_hash: record.roster_hash,
        transcript_hash: record.transcript_hash,
    };
    let session = validate_global_threshold_beacon_session_v1(&record, &binding, budget)?;
    Ok(DeterministicFixtureV1 {
        session,
        parameters,
        dealer_secrets,
        dealer_commitments,
    })
}

/// Derive the exact unactivated public key record installed by the network test.
///
/// This exports public transcript material only. No private share or dealer
/// secret is returned, serialized, or logged.
pub fn deterministic_parliament_beacon_key_record_v1(
    network_id: NetworkId,
    ordered_roster: &[PeerId],
    budget: &AllocationBudget,
) -> Result<
    FinalizedGlobalThresholdBeaconKeySessionRecordV1,
    TestNetworkParliamentBeaconSignerErrorV1,
> {
    let fixture = deterministic_fixture_v1(network_id, ordered_roster, false, budget)?;
    FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(fixture.session.record().clone(), budget)
        .map_err(TestNetworkParliamentBeaconSignerErrorV1::Session)
}

/// Derive the domain-separated successor record used by the rotation corridor.
///
/// This is a second complete adaptive-DKG transcript, not an alias for the
/// initial key. Like the initial fixture, it exports public material only.
pub fn deterministic_parliament_beacon_successor_key_record_v1(
    network_id: NetworkId,
    ordered_roster: &[PeerId],
    budget: &AllocationBudget,
) -> Result<
    FinalizedGlobalThresholdBeaconKeySessionRecordV1,
    TestNetworkParliamentBeaconSignerErrorV1,
> {
    let fixture = deterministic_fixture_v1(network_id, ordered_roster, true, budget)?;
    FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(fixture.session.record().clone(), budget)
        .map_err(TestNetworkParliamentBeaconSignerErrorV1::Session)
}

/// Runtime-only signer bound to one exact peer seat in one exact ordered roster.
///
/// The object stores no scalar share. It re-derives the feature-only deterministic
/// fixture for the caller-supplied validated session, requires byte-for-byte
/// public-record equality, produces one share, and immediately drops the
/// zeroizing temporary secret material.
pub struct TestNetworkParliamentBeaconPartialSignerV1 {
    network_id: NetworkId,
    ordered_roster: Vec<PeerId>,
    local_signer_index: u16,
    emit_invalid_outbound: bool,
    budget: AllocationBudget,
}

impl TestNetworkParliamentBeaconPartialSignerV1 {
    /// Bind the provider to the exact network and local peer seat.
    pub fn try_new(
        network_id: NetworkId,
        ordered_roster: Vec<PeerId>,
        local_peer: &PeerId,
        budget: &AllocationBudget,
    ) -> Result<Self, TestNetworkParliamentBeaconSignerErrorV1> {
        validate_roster_v1(&ordered_roster)?;
        let matching = ordered_roster
            .iter()
            .enumerate()
            .filter(|(_, peer)| *peer == local_peer)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(TestNetworkParliamentBeaconSignerErrorV1::InvalidLocalSeat);
        }
        let local_signer_index = u16::try_from(matching[0] + 1)
            .map_err(|_| TestNetworkParliamentBeaconSignerErrorV1::InvalidLocalSeat)?;
        Ok(Self {
            network_id,
            ordered_roster,
            local_signer_index,
            emit_invalid_outbound: false,
            budget: budget.clone(),
        })
    }

    /// Mark this feature-only provider as an adversarial outbound signer.
    ///
    /// The provider still derives a proof-valid share. The Sumeragi test hook
    /// corrupts that share only after signing, omits it from the local reducer,
    /// and broadcasts it so every receiving validator must reject it through
    /// the ordinary ingress verifier.
    #[must_use]
    pub fn with_deliberately_invalid_outbound(mut self) -> Self {
        self.emit_invalid_outbound = true;
        self
    }
}

impl GlobalThresholdBeaconPartialSignerV1 for TestNetworkParliamentBeaconPartialSignerV1 {
    fn attest_partial_signing_capability(
        &self,
        _session: &ValidatedGlobalThresholdBeaconSessionV1,
        _expected_signer_index: u16,
    ) -> Result<
        super::GlobalThresholdBeaconPartialSigningCapabilityV1,
        super::GlobalThresholdBeaconCapabilityErrorV1,
    > {
        // Deterministic test-only keys cannot attest production readiness.
        Err(super::GlobalThresholdBeaconCapabilityErrorV1::NotOwned)
    }

    fn sign_partial(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<GlobalThresholdBeaconPartialSignatureV1, String> {
        let initial_fixture =
            deterministic_fixture_v1(self.network_id, &self.ordered_roster, false, &self.budget)
                .map_err(|_| "test Parliament beacon fixture is unavailable".to_owned())?;
        let fixture = if initial_fixture.session.record() == session.record() {
            initial_fixture
        } else {
            let successor_fixture =
                deterministic_fixture_v1(self.network_id, &self.ordered_roster, true, &self.budget)
                    .map_err(|_| {
                        "test Parliament successor beacon fixture is unavailable".to_owned()
                    })?;
            if successor_fixture.session.record() != session.record() {
                return Err("test Parliament beacon session binding differs".to_owned());
            }
            successor_fixture
        };
        let private_contributions = fixture
            .dealer_secrets
            .iter()
            .zip(&fixture.dealer_commitments)
            .map(|(secret, dealer)| {
                secret.private_share(&fixture.parameters, dealer, self.local_signer_index)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "test Parliament beacon share derivation failed".to_owned())?;
        let share = AdaptiveThresholdBlsSecretShare::from_dealer_shares(
            fixture.session.transcript(),
            &private_contributions,
        )
        .map_err(|_| "test Parliament beacon share validation failed".to_owned())?;
        let signer = InMemoryGlobalThresholdBeaconPartialSignerV1::from_validated_share(
            fixture.session,
            share,
        )
        .map_err(|_| "test Parliament beacon signer import failed".to_owned())?;
        signer.sign_partial(session, payload)
    }

    fn test_network_emit_invalid_outbound_partial_v1(&self) -> bool {
        self.emit_invalid_outbound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_data_model::block::BlockHeader;

    fn network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x71; 32]),
        ))
    }

    fn roster() -> Vec<PeerId> {
        (1_u8..=4)
            .map(|tag| {
                let key = KeyPair::try_from_seed(vec![tag; 32], Algorithm::BlsNormal)
                    .expect("derive test BLS peer key");
                PeerId::new(key.public_key().clone())
            })
            .collect()
    }

    #[test]
    fn exact_seat_signer_matches_the_public_fixture_and_rejects_foreign_roster() {
        let roster = roster();
        let record = deterministic_parliament_beacon_key_record_v1(
            network_id(),
            &roster,
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("derive public fixture");
        let binding = GlobalThresholdBeaconSessionBindingV1 {
            network_id: record.session.network_id,
            session_id: record.session.session_id,
            roster_hash: record.session.roster_hash,
            transcript_hash: record.session.transcript_hash,
        };
        let validated = validate_global_threshold_beacon_session_v1(
            &(record.session),
            &binding,
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("validate public fixture");
        let payload = b"exact feature-isolated test payload";
        for peer in &roster {
            let signer = TestNetworkParliamentBeaconPartialSignerV1::try_new(
                network_id(),
                roster.clone(),
                peer,
                &crate::beacon::fixtures::fixture_budget(),
            )
            .expect("bind exact test seat");
            let partial = signer
                .sign_partial(&validated, payload)
                .expect("produce proof-valid share");
            let partial = super::super::adaptive_partial_signature_from_dto_v1(&partial)
                .expect("decode partial share");
            validated
                .transcript()
                .verify_partial_signature(payload, &partial)
                .expect("independently verify test share");
        }
        let mut foreign = roster.clone();
        foreign.swap(0, 1);
        let signer = TestNetworkParliamentBeaconPartialSignerV1::try_new(
            network_id(),
            foreign,
            &roster[0],
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("bind seat in a different ordered roster");
        assert!(signer.sign_partial(&validated, payload).is_err());

        let foreign_network = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x73; 32])),
        );
        let signer = TestNetworkParliamentBeaconPartialSignerV1::try_new(
            foreign_network,
            roster.clone(),
            &roster[0],
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("bind exact seat to a different network");
        assert!(signer.sign_partial(&validated, payload).is_err());
    }

    #[test]
    fn exact_seat_signer_supports_one_domain_separated_successor_session() {
        let roster = roster();
        let initial = deterministic_parliament_beacon_key_record_v1(
            network_id(),
            &roster,
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("derive initial public fixture");
        let successor = deterministic_parliament_beacon_successor_key_record_v1(
            network_id(),
            &roster,
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("derive successor public fixture");
        assert_ne!(initial.session.session_id, successor.session.session_id);
        assert_ne!(
            initial.session.transcript_hash,
            successor.session.transcript_hash
        );
        let binding = GlobalThresholdBeaconSessionBindingV1 {
            network_id: successor.session.network_id,
            session_id: successor.session.session_id,
            roster_hash: successor.session.roster_hash,
            transcript_hash: successor.session.transcript_hash,
        };
        let validated = validate_global_threshold_beacon_session_v1(
            &(successor.session),
            &binding,
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("validate successor public fixture");
        let payload = b"exact feature-isolated successor payload";
        for peer in &roster {
            let signer = TestNetworkParliamentBeaconPartialSignerV1::try_new(
                network_id(),
                roster.clone(),
                peer,
                &crate::beacon::fixtures::fixture_budget(),
            )
            .expect("bind exact successor test seat");
            let partial = signer
                .sign_partial(&validated, payload)
                .expect("produce successor proof-valid share");
            let partial = super::super::adaptive_partial_signature_from_dto_v1(&partial)
                .expect("decode successor partial share");
            validated
                .transcript()
                .verify_partial_signature(payload, &partial)
                .expect("independently verify successor test share");
        }
    }

    #[test]
    fn invalid_outbound_mode_preserves_valid_signing_and_sets_only_the_test_hook() {
        let roster = roster();
        let record = deterministic_parliament_beacon_key_record_v1(
            network_id(),
            &roster,
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("derive public fixture");
        let binding = GlobalThresholdBeaconSessionBindingV1 {
            network_id: record.session.network_id,
            session_id: record.session.session_id,
            roster_hash: record.session.roster_hash,
            transcript_hash: record.session.transcript_hash,
        };
        let validated = validate_global_threshold_beacon_session_v1(
            &(record.session),
            &binding,
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("validate public fixture");
        let signer = TestNetworkParliamentBeaconPartialSignerV1::try_new(
            network_id(),
            roster.clone(),
            &roster[0],
            &crate::beacon::fixtures::fixture_budget(),
        )
        .expect("bind exact test seat")
        .with_deliberately_invalid_outbound();
        let payload = b"feature-isolated invalid-outbound fixture";
        let partial = signer
            .sign_partial(&validated, payload)
            .expect("the provider itself must still produce a valid share");
        let decoded = super::super::adaptive_partial_signature_from_dto_v1(&partial)
            .expect("decode proof-valid provider output");
        validated
            .transcript()
            .verify_partial_signature(payload, &decoded)
            .expect("the corruption belongs to the outbound lifecycle hook");
        assert!(signer.test_network_emit_invalid_outbound_partial_v1());
    }
}
