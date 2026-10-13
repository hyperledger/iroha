//! Feature-isolated TLE signer for genuine Parliament network tests.
//!
//! This module is compiled only into the dedicated test daemon. It derives one
//! deterministic proof-valid adaptive-DKG share for the exact local seat in an
//! exact four-validator roster. It returns only a Core-authorized public partial
//! release; ordinary transcript, identity, height, proof, combine, and reducer
//! verification remain unchanged.

#[cfg(not(debug_assertions))]
compile_error!(
    "the feature-isolated Parliament TLE fixture signer cannot be compiled into optimized code"
);

use super::{
    AuthorizedTleReleaseContextV1, InMemoryTlePartialReleaseSignerV1, TleKeySessionPublicStateV1,
    TlePartialReleaseShareV1, TlePartialReleaseSignerV1, ValidatedTleKeySessionV1,
};
use crate::beacon::global_threshold_beacon_roster_hash_v1;
use iroha_crypto::{
    Hash,
    threshold_bls::{
        AdaptiveThresholdBlsParameters, AdaptiveThresholdBlsSecretShare, DasRenDealerSecret,
        ThresholdBlsSession, TleReleasePurpose, ValidatedDealerCommitment,
    },
};
use iroha_data_model::NetworkId;
use iroha_model_base::peer::PeerId;
use rand::{SeedableRng as _, rngs::StdRng};
use thiserror::Error;

const EXACT_TEST_VALIDATORS_V1: usize = 4;
const EXACT_TEST_THRESHOLD_V1: u16 = 2;
const TEST_SESSION_ID_DOMAIN_V1: &[u8] = b"iroha.test-network.parliament-tle.session.v1\0";
const TEST_DEALER_SEED_DOMAIN_V1: &[u8] = b"iroha.test-network.parliament-tle.dealers.v1\0";
const TEST_EVENT_HASH_DOMAIN_V1: &[u8] = b"iroha.test-network.parliament-tle.event.v1\0";

/// Closed construction failure for the feature-isolated Parliament TLE fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TestNetworkParliamentTleSignerErrorV1 {
    /// The fixture is intentionally limited to the exact four-validator corridor.
    #[error("test Parliament TLE signer requires exactly four distinct validators")]
    InvalidRoster,
    /// The configured local peer does not occupy exactly one frozen roster seat.
    #[error("local test Parliament TLE signer seat is not exact")]
    InvalidLocalSeat,
    /// The deterministic adaptive-DKG transcript or derived share was rejected.
    #[error("test Parliament TLE cryptographic fixture is invalid")]
    InvalidCryptographicFixture,
}

struct DeterministicFixtureV1 {
    session: ValidatedTleKeySessionV1,
    parameters: AdaptiveThresholdBlsParameters<TleReleasePurpose>,
    dealer_secrets: Vec<DasRenDealerSecret<TleReleasePurpose>>,
    dealer_commitments: Vec<ValidatedDealerCommitment<TleReleasePurpose>>,
}

fn validate_roster_v1(roster: &[PeerId]) -> Result<(), TestNetworkParliamentTleSignerErrorV1> {
    if roster.len() != EXACT_TEST_VALIDATORS_V1
        || roster
            .iter()
            .enumerate()
            .any(|(index, peer)| roster[index + 1..].contains(peer))
    {
        return Err(TestNetworkParliamentTleSignerErrorV1::InvalidRoster);
    }
    Ok(())
}

fn deterministic_fixture_v1(
    network_id: NetworkId,
    roster: &[PeerId],
) -> Result<DeterministicFixtureV1, TestNetworkParliamentTleSignerErrorV1> {
    validate_roster_v1(roster)?;
    let roster_hash = global_threshold_beacon_roster_hash_v1(roster);
    let mut session_id: [u8; 32] = Hash::new_from_chunks(&[
        TEST_SESSION_ID_DOMAIN_V1,
        network_id.as_bytes(),
        &roster_hash,
    ])
    .into();
    if session_id == [0; 32] {
        session_id[0] = 1;
    }
    let threshold_session = ThresholdBlsSession::<TleReleasePurpose>::new(
        *network_id.as_bytes(),
        session_id,
        roster_hash,
        u16::try_from(EXACT_TEST_VALIDATORS_V1).expect("fixture value fits u16"),
        EXACT_TEST_THRESHOLD_V1,
    )
    .map_err(|_| TestNetworkParliamentTleSignerErrorV1::InvalidCryptographicFixture)?;
    let parameters = AdaptiveThresholdBlsParameters::derive(&threshold_session)
        .map_err(|_| TestNetworkParliamentTleSignerErrorV1::InvalidCryptographicFixture)?;
    let dealer_seed: [u8; 32] = Hash::new_from_chunks(&[
        TEST_DEALER_SEED_DOMAIN_V1,
        network_id.as_bytes(),
        &session_id,
        &roster_hash,
    ])
    .into();
    let mut rng = StdRng::from_seed(dealer_seed);
    let mut dealer_secrets = Vec::with_capacity(EXACT_TEST_VALIDATORS_V1);
    let mut dealer_commitments = Vec::with_capacity(EXACT_TEST_VALIDATORS_V1);
    for dealer_index in
        1_u16..=u16::try_from(EXACT_TEST_VALIDATORS_V1).expect("fixture value fits u16")
    {
        let (secret, commitment) =
            DasRenDealerSecret::generate_with_rng(&parameters, dealer_index, &mut rng)
                .map_err(|_| TestNetworkParliamentTleSignerErrorV1::InvalidCryptographicFixture)?;
        dealer_secrets.push(secret);
        dealer_commitments.push(commitment);
    }
    let qualified_dealers = (1_u16
        ..=u16::try_from(EXACT_TEST_VALIDATORS_V1).expect("fixture value fits u16"))
        .collect::<Vec<_>>();
    let dkg_event_hash: [u8; 32] = Hash::new_from_chunks(&[
        TEST_EVENT_HASH_DOMAIN_V1,
        network_id.as_bytes(),
        &session_id,
        &roster_hash,
    ])
    .into();
    let session = ValidatedTleKeySessionV1::from_qualified_dealers(
        threshold_session,
        &dealer_commitments,
        &qualified_dealers,
        dkg_event_hash,
    )
    .map_err(|_| TestNetworkParliamentTleSignerErrorV1::InvalidCryptographicFixture)?;
    Ok(DeterministicFixtureV1 {
        session,
        parameters,
        dealer_secrets,
        dealer_commitments,
    })
}

/// Derive the exact public TLE key state installed by the network test.
///
/// This exports public transcript material only. No private share or dealer
/// secret is returned, serialized, or logged.
pub fn deterministic_parliament_tle_key_public_state_v1(
    network_id: NetworkId,
    ordered_roster: &[PeerId],
) -> Result<TleKeySessionPublicStateV1, TestNetworkParliamentTleSignerErrorV1> {
    Ok(deterministic_fixture_v1(network_id, ordered_roster)?
        .session
        .public_state()
        .clone())
}

/// Runtime-only TLE signer bound to one exact peer seat and network lineage.
///
/// The object stores no scalar share. It re-derives the feature-only fixture,
/// requires byte-for-byte public-state equality with Core authorization,
/// produces one proof-carrying share, and immediately drops the zeroizing
/// temporary secret material.
pub struct TestNetworkParliamentTlePartialReleaseSignerV1 {
    network_id: NetworkId,
    ordered_roster: Vec<PeerId>,
    local_signer_index: u16,
}

impl TestNetworkParliamentTlePartialReleaseSignerV1 {
    /// Bind the provider to the exact network and local validator seat.
    pub fn try_new(
        network_id: NetworkId,
        ordered_roster: Vec<PeerId>,
        local_peer: &PeerId,
    ) -> Result<Self, TestNetworkParliamentTleSignerErrorV1> {
        validate_roster_v1(&ordered_roster)?;
        let matching = ordered_roster
            .iter()
            .enumerate()
            .filter(|(_, peer)| *peer == local_peer)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(TestNetworkParliamentTleSignerErrorV1::InvalidLocalSeat);
        }
        let local_signer_index = u16::try_from(matching[0] + 1)
            .map_err(|_| TestNetworkParliamentTleSignerErrorV1::InvalidLocalSeat)?;
        Ok(Self {
            network_id,
            ordered_roster,
            local_signer_index,
        })
    }
}

impl TlePartialReleaseSignerV1 for TestNetworkParliamentTlePartialReleaseSignerV1 {
    fn attest_partial_release_capability(
        &self,
        session: &ValidatedTleKeySessionV1,
        expected_participant_index: u16,
    ) -> Result<
        super::TlePartialReleaseCapabilityAttestationV1,
        super::TlePartialReleaseCapabilityErrorV1,
    > {
        if expected_participant_index != self.local_signer_index {
            return Err(super::TlePartialReleaseCapabilityErrorV1::NotOwned);
        }
        let fixture = deterministic_fixture_v1(self.network_id, &self.ordered_roster)
            .map_err(|_| super::TlePartialReleaseCapabilityErrorV1::Unavailable)?;
        if fixture.session.public_state() != session.public_state() {
            return Err(super::TlePartialReleaseCapabilityErrorV1::NotOwned);
        }
        super::TlePartialReleaseCapabilityAttestationV1::for_validated_session(
            session,
            expected_participant_index,
        )
    }

    fn sign_partial_release(
        &self,
        context: &AuthorizedTleReleaseContextV1,
    ) -> Result<TlePartialReleaseShareV1, String> {
        let fixture = deterministic_fixture_v1(self.network_id, &self.ordered_roster)
            .map_err(|_| "test Parliament TLE fixture is unavailable".to_owned())?;
        if fixture.session.public_state() != context.session().public_state() {
            return Err("test Parliament TLE session binding differs".to_owned());
        }
        let private_contributions = fixture
            .dealer_secrets
            .iter()
            .zip(&fixture.dealer_commitments)
            .map(|(secret, dealer)| {
                secret.private_share(&fixture.parameters, dealer, self.local_signer_index)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "test Parliament TLE share derivation failed".to_owned())?;
        let share = AdaptiveThresholdBlsSecretShare::from_dealer_shares(
            fixture.session.transcript(),
            &private_contributions,
        )
        .map_err(|_| "test Parliament TLE share validation failed".to_owned())?;
        let signer =
            InMemoryTlePartialReleaseSignerV1::from_validated_share(fixture.session, share)
                .map_err(|_| "test Parliament TLE signer import failed".to_owned())?;
        signer.sign_partial_release(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::timed_ovn::TimedOvnReleaseIdentityPublicV1;
    use iroha_crypto::{Algorithm, HashOf, KeyPair, tle::TleReleaseIdentityV1};
    use iroha_data_model::{block::BlockHeader, governance::types::BallotAttemptId};

    fn network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x72; 32]),
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
    fn public_fixture_is_exact_for_every_local_seat() {
        let roster = roster();
        let public = deterministic_parliament_tle_key_public_state_v1(network_id(), &roster)
            .expect("derive public TLE fixture");
        public
            .clone()
            .validate()
            .expect("revalidate public TLE fixture");
        for peer in &roster {
            let signer = TestNetworkParliamentTlePartialReleaseSignerV1::try_new(
                network_id(),
                roster.clone(),
                peer,
            )
            .expect("bind exact test TLE seat");
            assert!(signer.local_signer_index >= 1);
        }
        let mut foreign = roster.clone();
        foreign.swap(0, 1);
        let foreign_public =
            deterministic_parliament_tle_key_public_state_v1(network_id(), &foreign)
                .expect("derive foreign ordered-roster fixture");
        assert_ne!(public, foreign_public);
    }

    #[test]
    fn exact_local_seat_returns_one_independently_verifiable_partial() {
        let roster = roster();
        let fixture = deterministic_fixture_v1(network_id(), &roster)
            .expect("derive private test-only fixture");
        let threshold_session = *fixture.session.transcript().session();
        let identity = TleReleaseIdentityV1::new(
            threshold_session,
            [0x10; 32],
            [0x11; 32],
            [0x12; 32],
            [0x13; 32],
            [0x14; 32],
            100,
            [0x15; 32],
        )
        .expect("construct exact future release identity");
        let context = AuthorizedTleReleaseContextV1 {
            ballot_attempt_id: BallotAttemptId::new([0x12; 32]),
            opening_deadline_height: 110,
            finalized_height: 100,
            public_release_identity: TimedOvnReleaseIdentityPublicV1 {
                tle_key_session_id: fixture.session.public_state().key_session_id,
                governance_attempt_id: [0x10; 32],
                body_instance_id: [0x11; 32],
                ballot_attempt_id: [0x12; 32],
                survivor_corpus_root: [0x13; 32],
                no_recovery_root: [0x14; 32],
                target_finalized_height: 100,
                parameter_hash: [0x15; 32],
            },
            identity,
            session: fixture.session,
        };
        let foreign_network = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x74; 32])),
        );
        let foreign_signer = TestNetworkParliamentTlePartialReleaseSignerV1::try_new(
            foreign_network,
            roster.clone(),
            &roster[0],
        )
        .expect("bind exact seat to a different network");
        assert!(foreign_signer.sign_partial_release(&context).is_err());
        let signer = TestNetworkParliamentTlePartialReleaseSignerV1::try_new(
            network_id(),
            roster.clone(),
            &roster[0],
        )
        .expect("bind first exact TLE seat");
        let partial = signer
            .sign_partial_release(&context)
            .expect("produce proof-carrying partial release");
        context
            .session()
            .verify_partial_release(context.identity(), context.finalized_height(), &partial)
            .expect("independently verify the exact returned share");
    }
}
