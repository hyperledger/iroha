//! Beacon protocol, DKG, and Parliament regression tests.

use super::{
    fixtures::{
        AdaptiveBeaconFixture, adaptive_beacon_fixture, adaptive_beacon_fixture_for_session,
        adaptive_beacon_fixture_for_session_and_keys, adaptive_dkg_session_fixture,
        beacon_fixture_network_id,
    },
    *,
};
use crate::{
    governance::parliament::{
        ParliamentAttemptStateV1, ParliamentDecisionModeV1, RequiredParliamentBodyV1,
    },
    state::{GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, World, WorldReadOnly as _},
};
use iroha_config::parameters::actual::LaneConfig as RuntimeLaneConfig;
use iroha_crypto::{
    Algorithm, HashOf, KeyPair,
    threshold_bls::{AdaptiveThresholdBlsSecretShare, TleReleasePurpose},
};
use iroha_data_model::{
    account::AccountId,
    block::BlockHeader,
    governance::types::{
        BeaconSessionId, BodyElectionAttemptId, GovernanceAttemptId, GovernanceAttemptStatusV1,
        GovernanceAttemptV1, GovernanceExpectedHeadAbsentV1, GovernanceExpectedHeadV1,
        GovernanceStageV1, MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1, ParliamentBody,
        ProposalContentId, RiskTierV1, SortitionRequestId, SortitionRequestV1,
        parliament_candidate_root_v1,
    },
};
use iroha_model_base::peer::PeerId;
use rand::rngs::StdRng;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn invalid_session(error: GlobalThresholdBeaconSessionError) -> GlobalThresholdBeaconError {
    match error {
        GlobalThresholdBeaconSessionError::Invalid(error) => error,
        original => panic!(
            "expected completed canonical rejection, got original local failure: {original:?}"
        ),
    }
}

#[test]
fn active_global_beacon_session_projection_rejects_noncanonical_storage() {
    let world = World::new();
    assert_eq!(
        active_global_threshold_beacon_session_id_v1(&world.view()),
        Ok(None)
    );

    let canonical = [0x31; 32];
    {
        let mut block = world.block();
        block
            .global_beacon_active_session
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, canonical);
        block.commit();
    }
    assert_eq!(
        active_global_threshold_beacon_session_id_v1(&world.view()),
        Ok(Some(canonical))
    );

    {
        let mut block = world.block();
        block
            .global_beacon_active_session
            .remove(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY);
        block.global_beacon_active_session.insert(1, [0x41; 32]);
        block.commit();
    }
    assert_eq!(
        active_global_threshold_beacon_session_id_v1(&world.view()),
        Err(GlobalThresholdBeaconError::PersistenceConflict)
    );

    {
        let mut block = world.block();
        block
            .global_beacon_active_session
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, canonical);
        block.commit();
    }
    assert_eq!(
        active_global_threshold_beacon_session_id_v1(&world.view()),
        Err(GlobalThresholdBeaconError::PersistenceConflict)
    );
}

fn complete_dkg_fixture(seats: u16) -> AdaptiveBeaconFixture {
    let mut session = adaptive_dkg_session_fixture();
    session.committee_size = seats;
    session.threshold = (seats - 1) / 3 + 1;
    let keys = super::fixtures::adaptive_fixture_signing_keys(seats);
    session.roster_hash = global_threshold_beacon_roster_hash_v1(
        &keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>(),
    );
    adaptive_beacon_fixture_for_session_and_keys(session, &keys, &super::fixtures::fixture_budget())
}

fn replay_dkg_until_finalizable(
    transcript: &GlobalThresholdBeaconDkgTranscriptV1,
    edge_count: usize,
) -> GlobalThresholdBeaconDkgStateV1 {
    let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
    let session = transcript.session;
    let mut state =
        GlobalThresholdBeaconDkgStateV1::new(session, &crypto, &super::fixtures::fixture_budget())
            .expect("valid DKG session");
    for key in &transcript.recipient_keys {
        state
            .record_recipient_key(session.start_height, key)
            .expect("signed recipient key");
    }
    for commitment in &transcript.dealer_commitments {
        state
            .record_dealer_commitment(session.start_height, commitment, &crypto)
            .expect("verified dealer commitment");
    }
    for edge in transcript.encrypted_shares.iter().take(edge_count) {
        state
            .record_encrypted_share(session.commitments_end_height, edge)
            .expect("signed encrypted edge");
    }
    for acceptance in transcript.share_acceptances.iter().take(edge_count) {
        state
            .record_share_acceptance(session.deliveries_end_height, acceptance)
            .expect("signed edge acceptance");
    }
    state
}

#[test]
fn adaptive_dkg_reducer_requires_every_signed_private_edge_at_four_and_seven_seats() {
    let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
    for seats in [4, 7] {
        let fixture = complete_dkg_fixture(seats);
        let transcript = &fixture.session.record().adaptive_dkg;
        let all_edges = usize::from(seats) * usize::from(seats);
        assert_eq!(transcript.encrypted_shares.len(), all_edges);
        assert_eq!(transcript.share_acceptances.len(), all_edges);
        assert_eq!(
            transcript.qualified_dealers,
            (1..=seats).collect::<Vec<_>>()
        );
        let mut complete = replay_dkg_until_finalizable(transcript, all_edges);
        assert_eq!(
            complete
                .finalize(transcript.finalized_at_height, &crypto)
                .expect("complete all-edge DKG")
                .adaptive_dkg,
            *transcript
        );
        let mut missing = replay_dkg_until_finalizable(transcript, all_edges - 1);
        assert!(matches!(
            missing.finalize(transcript.finalized_at_height, &crypto),
            Err(GlobalThresholdBeaconSessionError::Invalid(
                GlobalThresholdBeaconError::IncompleteDkgEdges
            ))
        ));
        assert_eq!(
            missing.phase_at(transcript.finalized_at_height + 1),
            GlobalThresholdBeaconDkgPhaseV1::Aborted
        );
        // Public transcript bytes never contain the plaintext verified share
        // triple that travelled only through authenticated encryption.
        let private = fixture.dealer_secrets[0]
            .private_share(&fixture.parameters, &fixture.dealer_commitments[0], 1)
            .expect("verified private fixture share");
        let scalar_bytes = private.components_for_authenticated_encryption();
        let public_bytes = transcript.encode();
        for scalar in scalar_bytes.iter() {
            assert!(!public_bytes.windows(32).any(|window| window == scalar));
        }
    }
}

#[test]
fn adaptive_dkg_rejects_out_of_phase_and_replayed_attempt_edges() {
    let fixture = complete_dkg_fixture(4);
    let transcript = &fixture.session.record().adaptive_dkg;
    let session = transcript.session;
    let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
    let mut state =
        GlobalThresholdBeaconDkgStateV1::new(session, &crypto, &super::fixtures::fixture_budget())
            .expect("valid DKG state");
    assert!(matches!(
        state.record_encrypted_share(session.start_height, &transcript.encrypted_shares[0]),
        Err(GlobalThresholdBeaconSessionError::Invalid(
            GlobalThresholdBeaconError::WrongDkgPhase
        ))
    ));
    for key in &transcript.recipient_keys {
        state
            .record_recipient_key(session.start_height, key)
            .expect("recipient key");
    }
    for commitment in &transcript.dealer_commitments {
        state
            .record_dealer_commitment(session.start_height, commitment, &crypto)
            .expect("dealer commitment");
    }
    let edge = &transcript.encrypted_shares[0];
    let mut other_attempt = session;
    other_attempt.attempt_id[0] ^= 1;
    assert_eq!(
        verify_global_threshold_beacon_dkg_encrypted_share_v1(
            &other_attempt,
            &transcript.dealer_commitments[0],
            &transcript.recipient_keys[0],
            &transcript.recipient_keys[0],
            edge,
        ),
        Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare)
    );
    state
        .record_encrypted_share(session.commitments_end_height, edge)
        .expect("first edge");
    let mut equivocated = edge.clone();
    equivocated.encrypted_share[12] ^= 1;
    assert!(matches!(
        state.record_encrypted_share(session.commitments_end_height, &equivocated),
        Err(GlobalThresholdBeaconSessionError::Invalid(
            GlobalThresholdBeaconError::InvalidDkgEncryptedShare
        ))
    ));
}

#[test]
fn adaptive_dkg_public_snapshot_roundtrips_and_restores() {
    let fixture = complete_dkg_fixture(4);
    let transcript = &fixture.session.record().adaptive_dkg;
    let state = replay_dkg_until_finalizable(transcript, 16);
    let snapshot = state.public_snapshot().expect("public snapshot");
    let bytes = norito::to_bytes(&snapshot).expect("encode public DKG snapshot");
    let binary: GlobalThresholdBeaconDkgSnapshotV1 =
        norito::decode_from_bytes(&bytes).expect("decode public DKG snapshot");
    binary.validate().expect("validate decoded DKG snapshot");
    crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
        snapshot.record(),
        "iroha_core::beacon::GlobalThresholdBeaconDkgSnapshotV1",
    );
    assert!(matches!(
        norito::decode_canonical::<GlobalThresholdBeaconKeySessionV1>(&bytes),
        Err(norito::Error::SchemaMismatch),
    ));
    assert_eq!(&binary, snapshot.record());
    let json = norito::json::to_json(snapshot.record()).expect("encode public DKG snapshot JSON");
    let decoded_json: GlobalThresholdBeaconDkgSnapshotV1 =
        norito::json::from_str(&json).expect("decode public DKG snapshot JSON");
    assert_eq!(&decoded_json, snapshot.record());
    let restored = GlobalThresholdBeaconDkgStateV1::from_snapshot(
        &binary,
        &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
        state.allocation_budget(),
    )
    .expect("cryptographically restore public snapshot");
    assert_eq!(
        restored
            .public_snapshot()
            .expect("restored snapshot")
            .record(),
        snapshot.record()
    );
}

#[test]
fn finalized_key_lifecycle_is_strict_and_roundtrips() {
    let (validated, _) = validated_threshold_session();
    let mut record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
        validated.record().clone(),
        &super::fixtures::fixture_budget(),
    )
    .expect("valid finalized public key record");
    let finalized_height = record.session.adaptive_dkg.finalized_at_height;
    assert_eq!(
        record
            .activate(finalized_height - 1, &super::fixtures::fixture_budget())
            .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::InvalidKeyLifecycle)
    );
    record
        .activate(finalized_height, &super::fixtures::fixture_budget())
        .map_err(invalid_session)
        .expect("activate at finalization height");
    assert!(record.is_active_at(finalized_height));
    assert_eq!(
        record
            .retire(finalized_height, &super::fixtures::fixture_budget())
            .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::InvalidKeyLifecycle)
    );
    record
        .retire(finalized_height + 1, &super::fixtures::fixture_budget())
        .map_err(invalid_session)
        .expect("strictly later retirement");
    assert!(!record.is_active_at(finalized_height + 1));
    let encoded = norito::to_bytes(&record).expect("encode key lifecycle");
    let decoded: FinalizedGlobalThresholdBeaconKeySessionRecordV1 =
        norito::decode_from_bytes(&encoded).expect("decode key lifecycle");
    decoded
        .validate(&super::fixtures::fixture_budget())
        .expect("validate decoded lifecycle");
    crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
        &record,
        "iroha_core::beacon::FinalizedGlobalThresholdBeaconKeySessionRecordV1",
    );
    assert!(matches!(
        norito::decode_canonical::<GlobalThresholdBeaconKeySessionV1>(&encoded),
        Err(norito::Error::SchemaMismatch),
    ));
    assert_eq!(decoded, record);
}

fn decode_fixed<const N: usize>(encoded: &str) -> [u8; N] {
    let compact = encoded
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .collect::<Vec<_>>();
    hex::decode(compact)
        .expect("hex test vector")
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
}

fn wrong_g1_signature() -> [u8; 48] {
    decode_fixed(
        "97f1d3a73197d7942695638c4fa9ac0f\
             c3688c4f9774b905a14e3a3f171bac58\
             6c55e83ff97a1aeffb3af00adb22c6bb",
    )
}

pub(crate) fn finalized_key_session_fixture_for_context_v1(
    network_id: NetworkId,
    session_id: [u8; 32],
    signing_keys: &[KeyPair],
) -> FinalizedGlobalThresholdBeaconKeySessionRecordV1 {
    let mut dkg_session = adaptive_dkg_session_fixture();
    dkg_session.network_id = network_id;
    dkg_session.session_id = session_id;
    dkg_session.roster_hash = global_threshold_beacon_roster_hash_v1(
        &signing_keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>(),
    );
    let fixture = adaptive_beacon_fixture_for_session_and_keys(
        dkg_session,
        signing_keys,
        &super::fixtures::fixture_budget(),
    );
    FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
        fixture.session.record().clone(),
        &super::fixtures::fixture_budget(),
    )
    .expect("proof-valid finalized global beacon key fixture")
}

/// One real finalized DKG retained across historical authorization and pulse construction.
/// This supplies cryptographic evidence only; it does not execute a native boundary in State.
/// Private-share encryption is randomized, so rebuilding an identically named session would
/// create a different transcript from the one authorized by the historical boundary.
pub(crate) struct HistoricalBeaconFixture(AdaptiveBeaconFixture);

impl HistoricalBeaconFixture {
    /// Complete the DKG once, retaining its exact transcript and private contributions.
    pub(crate) fn new(
        network_id: NetworkId,
        session_id: [u8; 32],
        authority_generation: u64,
        signing_keys: &[KeyPair],
    ) -> Self {
        let mut dkg_session = adaptive_dkg_session_fixture();
        dkg_session.network_id = network_id;
        dkg_session.session_id = session_id;
        dkg_session.attempt_id = session_id;
        dkg_session.authority_generation = authority_generation;
        dkg_session.committee_size = u16::try_from(signing_keys.len()).unwrap();
        dkg_session.threshold = (dkg_session.committee_size - 1) / 3 + 1;
        dkg_session.roster_hash = global_threshold_beacon_roster_hash_v1(
            &signing_keys
                .iter()
                .map(|key| PeerId::new(key.public_key().clone()))
                .collect::<Vec<_>>(),
        );
        dkg_session.commitments_end_height = 2;
        dkg_session.deliveries_end_height = 3;
        dkg_session.acceptances_end_height = 4;
        Self(adaptive_beacon_fixture_for_session_and_keys(
            dkg_session,
            signing_keys,
            &super::fixtures::fixture_budget(),
        ))
    }

    /// Public session authenticated by a boundary authorizing this fixture's later pulses.
    pub(crate) fn record(&self) -> &GlobalThresholdBeaconKeySessionV1 {
        self.0.session.record()
    }

    /// Produce a threshold pulse from the original DKG, bound to the exact parent.
    pub(crate) fn pulse(
        &self,
        anchor: GlobalThresholdBeaconChainAnchorV1,
        context: iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1,
    ) -> FinalizedGlobalThresholdBeaconPulseV1 {
        let fixture = &self.0;
        let height = anchor.height.checked_add(1).unwrap();
        assert!(height > 4, "pulse follows complete DKG finalization");
        let (mut template, _, _) = pulse_fixture(&fixture.session);
        template.height = height;
        template.finalized_chain_anchor = anchor;
        template.context = context;
        let mut aggregator = GlobalThresholdBeaconPulseAggregatorV1::new(
            fixture.session.clone(),
            height,
            anchor,
            context,
        )
        .unwrap();
        for partial in pulse_partial_signatures(fixture, &template, [0xA7; 32])
            .into_iter()
            .take(usize::from(
                fixture.session.transcript().session().threshold(),
            ))
        {
            aggregator.accept_partial(partial).unwrap();
        }
        let pulse = aggregator.finalize().unwrap();
        verify_finalized_global_threshold_beacon_pulse_v1(
            &fixture.session,
            &pulse,
            anchor,
            &context,
        )
        .unwrap();
        assert_eq!(pulse.session_id, self.record().session_id);
        assert_eq!(pulse.transcript_hash, self.record().transcript_hash);
        pulse
    }
}

/// Independent cryptographic mutation fixture; historical positive cases retain their DKG.
pub(crate) fn finalized_pulses_fixture_for_context_v1(
    network_id: NetworkId,
    session_id: [u8; 32],
    signing_keys: &[KeyPair],
    anchors: &[(
        GlobalThresholdBeaconChainAnchorV1,
        iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1,
    )],
) -> (
    FinalizedGlobalThresholdBeaconKeySessionRecordV1,
    Vec<FinalizedGlobalThresholdBeaconPulseV1>,
) {
    let fixture = HistoricalBeaconFixture::new(network_id, session_id, 1, signing_keys);
    let record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
        fixture.record().clone(),
        &super::fixtures::fixture_budget(),
    )
    .unwrap();
    let pulses = anchors
        .iter()
        .map(|(anchor, context)| fixture.pulse(*anchor, *context))
        .collect();
    (record, pulses)
}

fn validated_threshold_session() -> (
    ValidatedGlobalThresholdBeaconSessionV1,
    GlobalThresholdBeaconSessionBindingV1,
) {
    let fixture = adaptive_beacon_fixture();
    let validated = fixture.session;
    let expected = fixture.binding;
    (validated, expected)
}

fn pulse_fixture(
    session: &ValidatedGlobalThresholdBeaconSessionV1,
) -> (
    FinalizedGlobalThresholdBeaconPulseV1,
    GlobalThresholdBeaconPulseLinkV1,
    GlobalThresholdBeaconChainAnchorV1,
) {
    let cursor = GlobalThresholdBeaconPulseLinkV1 {
        pulse_id: [0x66; 32],
        seed: [0x77; 32],
        height: 0,
        round: 0,
    };
    let anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: 40,
        block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x88; 32])),
    };
    let record = session.record();
    (
        FinalizedGlobalThresholdBeaconPulseV1 {
            version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id: record.network_id,
            session_id: record.session_id,
            roster_hash: record.roster_hash,
            transcript_hash: record.transcript_hash,
            context: crate::beacon::pulse_context_fixture_v1(),
            height: 41,
            round: 0,
            finalized_chain_anchor: anchor,
            signature: wrong_g1_signature(),
            seed: [0x99; 32],
            pulse_id: [0xAA; 32],
        },
        cursor,
        anchor,
    )
}

fn signed_pulse_fixture() -> (
    AdaptiveBeaconFixture,
    FinalizedGlobalThresholdBeaconPulseV1,
    GlobalThresholdBeaconPulseLinkV1,
    GlobalThresholdBeaconChainAnchorV1,
) {
    let fixture = adaptive_beacon_fixture();
    let (pulse, cursor, anchor) = pulse_fixture(&fixture.session);
    let partials = pulse_partial_signatures(&fixture, &pulse, [0xA7; 32]);
    let mut aggregator = GlobalThresholdBeaconPulseAggregatorV1::new(
        fixture.session.clone(),
        pulse.height,
        anchor,
        pulse.context,
    )
    .expect("open exact pulse reducer");
    for partial in partials.into_iter().take(usize::from(
        fixture.session.transcript().session().threshold(),
    )) {
        aggregator
            .accept_partial(partial)
            .expect("accept proof-verified partial");
    }
    let pulse = aggregator.finalize().expect("finalize unique pulse");
    (fixture, pulse, cursor, anchor)
}

fn pulse_partial_signatures(
    fixture: &AdaptiveBeaconFixture,
    pulse: &FinalizedGlobalThresholdBeaconPulseV1,
    rng_seed: [u8; 32],
) -> Vec<GlobalThresholdBeaconPartialSignatureV1> {
    let payload = global_threshold_beacon_pulse_payload_v1(pulse);
    let mut proof_rng = StdRng::from_seed(rng_seed);
    let mut partials = Vec::new();

    for recipient_index in 1_u16..=fixture.session.transcript().session().committee_size() {
        let private_contributions = fixture
            .dealer_secrets
            .iter()
            .zip(&fixture.dealer_commitments)
            .map(|(secret, dealer)| {
                secret
                    .private_share(&fixture.parameters, dealer, recipient_index)
                    .expect("verified private DKG contribution")
            })
            .collect::<Vec<_>>();
        let signing_share = AdaptiveThresholdBlsSecretShare::from_dealer_shares(
            fixture.session.transcript(),
            &private_contributions,
        )
        .expect("aggregate exact qualified private contributions");
        partials.push(global_threshold_beacon_partial_signature_dto_v1(
            &signing_share
                .sign_payload_with_rng(fixture.session.transcript(), &payload, &mut proof_rng)
                .expect("adaptive signature share"),
        ));
    }
    partials
}

fn live_fixture_in_memory_signer(
    fixture: &AdaptiveBeaconFixture,
    recipient_index: u16,
) -> InMemoryGlobalThresholdBeaconPartialSignerV1 {
    let private_contributions = fixture
        .dealer_secrets
        .iter()
        .zip(&fixture.dealer_commitments)
        .map(|(secret, dealer)| {
            secret
                .private_share(&fixture.parameters, dealer, recipient_index)
                .expect("verified private DKG contribution")
        })
        .collect::<Vec<_>>();
    let share = AdaptiveThresholdBlsSecretShare::from_dealer_shares(
        fixture.session.transcript(),
        &private_contributions,
    )
    .expect("aggregate exact qualified private contributions");
    InMemoryGlobalThresholdBeaconPartialSignerV1::from_validated_share(
        fixture.session.clone(),
        share,
    )
    .expect("move the DKG share into the zeroizing runtime provider")
}

struct FailOnceBeaconSigner {
    inner: Arc<dyn GlobalThresholdBeaconPartialSignerV1>,
    attempts: Arc<AtomicUsize>,
}

impl GlobalThresholdBeaconPartialSignerV1 for FailOnceBeaconSigner {
    fn attest_partial_signing_capability(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalThresholdBeaconCapabilityErrorV1,
    > {
        self.inner
            .attest_partial_signing_capability(session, expected_signer_index)
    }

    fn sign_partial(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<GlobalThresholdBeaconPartialSignatureV1, String> {
        if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err("transient signer failure".to_owned());
        }
        self.inner.sign_partial(session, payload)
    }
}

#[test]
fn runtime_beacon_capability_requires_exact_live_session_and_seat_without_signing() {
    let fixture = adaptive_beacon_fixture();
    let custody = RuntimeGlobalThresholdBeaconShareCustodyV1::new();
    assert_eq!(
        custody.attest_partial_signing_capability(&fixture.session, 1),
        Err(GlobalThresholdBeaconCapabilityErrorV1::NotOwned)
    );
    for index in [0, 5] {
        assert_eq!(
            custody.attest_partial_signing_capability(&fixture.session, index),
            Err(GlobalThresholdBeaconCapabilityErrorV1::InvalidRequest)
        );
    }
    custody
        .insert_validated_share(live_fixture_in_memory_signer(&fixture, 1))
        .expect("own seat one");
    let attempts = Arc::new(AtomicUsize::new(0));
    let provider = FailOnceBeaconSigner {
        inner: Arc::new(custody),
        attempts: Arc::clone(&attempts),
    };
    let capability = provider
        .attest_partial_signing_capability(&fixture.session, 1)
        .expect("exact live custody");
    assert!(capability.matches(&fixture.session, 1));
    assert_eq!(capability.session_id(), fixture.session.record().session_id);
    assert_eq!(
        capability.transcript_hash(),
        fixture.session.record().transcript_hash
    );
    assert_eq!(capability.signer_index(), 1);
    assert!(!capability.matches(&fixture.session, 2));
    assert_eq!(
        provider.attest_partial_signing_capability(&fixture.session, 2),
        Err(GlobalThresholdBeaconCapabilityErrorV1::NotOwned)
    );
    let mut other = adaptive_dkg_session_fixture();
    other.session_id = [0xC7; 32];
    let other = adaptive_beacon_fixture_for_session(other);
    assert_eq!(
        provider.attest_partial_signing_capability(&other.session, 1),
        Err(GlobalThresholdBeaconCapabilityErrorV1::NotOwned)
    );
    assert!(!capability.matches(&other.session, 1));
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        0,
        "capability must never call sign_partial"
    );
}

#[test]
fn runtime_beacon_custody_selects_exact_rotating_session_and_rejects_replacement() {
    let fixture_a = adaptive_beacon_fixture();
    let mut session_b = adaptive_dkg_session_fixture();
    session_b.session_id = [0xB2; 32];
    let fixture_b = adaptive_beacon_fixture_for_session(session_b);
    let custody = RuntimeGlobalThresholdBeaconShareCustodyV1::new();
    custody
        .insert_validated_share(live_fixture_in_memory_signer(&fixture_a, 1))
        .expect("insert key-A share");
    custody
        .insert_validated_share(live_fixture_in_memory_signer(&fixture_b, 1))
        .expect("insert key-B share before key-A retirement");
    assert_eq!(
        custody.insert_validated_share(live_fixture_in_memory_signer(&fixture_a, 2)),
        Err(GlobalThresholdBeaconShareCustodyErrorV1::SessionAlreadyPresent),
    );

    for (fixture, height, anchor_byte) in [(&fixture_a, 41, 0xA1), (&fixture_b, 42, 0xB1)] {
        let anchor = GlobalThresholdBeaconChainAnchorV1 {
            height: height - 1,
            block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                [anchor_byte; 32],
            )),
        };
        let mut aggregator = GlobalThresholdBeaconPulseAggregatorV1::new(
            fixture.session.clone(),
            height,
            anchor,
            crate::beacon::pulse_context_fixture_v1(),
        )
        .expect("open rotating-session pulse");
        let partial = custody
            .sign_partial(&fixture.session, aggregator.payload())
            .expect("select exact session share");
        assert!(
            aggregator
                .accept_partial(partial)
                .expect("independently verify custody output")
        );
    }
}

fn live_producer_keys() -> Vec<KeyPair> {
    let mut keys = (1_u8..=4)
        .map(|marker| {
            KeyPair::try_from_seed(vec![marker; 32], Algorithm::BlsNormal)
                .expect("deterministic BLS validator key")
        })
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
    keys
}

pub(crate) fn pending_batched_sortition_attempt(
    network_id: &NetworkId,
    roster: &[PeerId],
    pulse_height: u64,
) -> (
    GovernanceAttemptId,
    Vec<SortitionRequestId>,
    ParliamentAttemptStateV1,
) {
    assert!(
        pulse_height > 1,
        "a pulse needs a positive predecessor request height"
    );
    let request_height = pulse_height.saturating_sub(10).max(1);
    // The fixture's frozen policy must describe the exact requested slot: the delay covers
    // pulses before height 11, where a ten-block delay is impossible, and the frozen epoch
    // length makes `pulse_height` the chain's first consensus-native pulse height.
    let pulse_delay = pulse_height - request_height;
    let pulse_epoch_length = pulse_height + 1;
    let (governance_attempt_id, request_ids, attempt, slot) =
        pending_batched_sortition_attempt_with_schedule(
            network_id,
            roster,
            request_height,
            pulse_delay,
            pulse_epoch_length,
        );
    assert_eq!(slot, pulse_height);
    (governance_attempt_id, request_ids, attempt)
}

/// The same pending two-body generation under an explicit frozen schedule: requested at
/// `request_height` with `pulse_delay` blocks of delay on a chain whose consensus-native
/// epoch is `pulse_epoch_length` blocks long. Also returns the frozen slot, the first native
/// pulse height at or after `request_height + pulse_delay`.
pub(crate) fn pending_batched_sortition_attempt_with_schedule(
    network_id: &NetworkId,
    roster: &[PeerId],
    request_height: u64,
    pulse_delay: u64,
    pulse_epoch_length: u64,
) -> (
    GovernanceAttemptId,
    Vec<SortitionRequestId>,
    ParliamentAttemptStateV1,
    u64,
) {
    let pulse_height = crate::governance::parliament::aligned_sortition_pulse_height_v1(
        request_height
            .checked_add(pulse_delay)
            .expect("fixture earliest pulse height fits"),
        pulse_epoch_length,
    )
    .expect("fixture schedule has a native pulse height");
    let proposal_content_id = ProposalContentId::new([0x41; 32]);
    let governance_attempt_id = GovernanceAttemptId::derive_v1(proposal_content_id, 0);
    let mut attempt = ParliamentAttemptStateV1::try_new(
        GovernanceAttemptV1 {
            id: governance_attempt_id,
            proposal_content_id,
            sequence: 0,
            risk_tier: RiskTierV1::Standard,
            stage: GovernanceStageV1::Qualification,
            status: GovernanceAttemptStatusV1::Active,
        },
        1,
        pulse_delay,
        pulse_epoch_length,
        [0x42; 32],
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: [0x43; 32],
        }),
        vec![
            RequiredParliamentBodyV1 {
                body: ParliamentBody::RulesCommittee,
                decision_mode: ParliamentDecisionModeV1::PublicFinding,
            },
            RequiredParliamentBodyV1 {
                body: ParliamentBody::PolicyJury,
                decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
            },
        ],
    )
    .expect("construct pending Parliament attempt");
    attempt
        .complete_qualification(governance_attempt_id)
        .expect("enter the first required body stage");
    let mut candidates = roster
        .iter()
        .map(|peer| AccountId::new(peer.public_key().clone()))
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    let mut request_ids = Vec::new();
    for body in [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury] {
        let election_attempt_id = BodyElectionAttemptId::derive_v1(governance_attempt_id, body, 0);
        let candidate_root = parliament_candidate_root_v1(governance_attempt_id, body, &candidates);
        let request = SortitionRequestV1::try_new_canonical(
            governance_attempt_id,
            election_attempt_id,
            body,
            candidate_root,
            u32::try_from(candidates.len()).expect("four candidates"),
            if body == ParliamentBody::PolicyJury {
                MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
            } else {
                2
            },
            request_height,
            pulse_height,
            BeaconSessionId::for_network_v1(network_id),
            None,
        )
        .expect("construct batched logical-beacon sortition request");
        request_ids.push(request.id);
        attempt
            .register_sortition_request(governance_attempt_id, 0, request, candidates.clone())
            .expect("register pending logical-beacon request");
    }
    request_ids.sort_unstable();
    (governance_attempt_id, request_ids, attempt, pulse_height)
}

#[test]
fn pending_sortition_fixture_admits_early_and_later_pulse_heights() {
    let network_id = beacon_fixture_network_id(0x85);
    let roster = live_producer_keys()
        .into_iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    for height in [2, 9, 10, 11, 41] {
        let (_, requests, attempt) =
            pending_batched_sortition_attempt(&network_id, &roster, height);
        assert_eq!(requests.len(), 2);
        let world = World::new();
        let mut block = world.block();
        let mut transaction = block.transaction_without_telemetry(RuntimeLaneConfig::default(), 0);
        transaction
            .put_parliament_attempt(attempt)
            .expect("canonical fixture admission");
        assert!(
            transaction
                .parliament_required_beacon_pulse_slots
                .get(&(BeaconSessionId::for_network_v1(&network_id), height))
                .is_some()
        );
    }
}

#[test]
fn threshold_beacon_session_validates_complete_canonical_transcript() {
    let (session, expected) = validated_threshold_session();
    assert_eq!(session.record().transcript_hash, expected.transcript_hash);
    assert_eq!(session.record().public_shares.len(), 4);
    assert_eq!(session.ensure_adaptive_protocol_ready(), Ok(()));
}

#[test]
fn threshold_beacon_session_rejects_wrong_bindings_and_malformed_points() {
    let (session, expected) = validated_threshold_session();
    let record = session.record().clone();

    let mut wrong_network = record.clone();
    wrong_network.network_id = beacon_fixture_network_id(0x82);
    assert_eq!(
        validate_global_threshold_beacon_session_v1(
            &(wrong_network),
            &expected,
            &super::fixtures::fixture_budget()
        )
        .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::NetworkMismatch)
    );

    let mut wrong_roster = record.clone();
    wrong_roster.roster_hash[0] ^= 1;
    assert_eq!(
        validate_global_threshold_beacon_session_v1(
            &(wrong_roster),
            &expected,
            &super::fixtures::fixture_budget()
        )
        .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::RosterMismatch)
    );

    let mut zero_roster = record.clone();
    zero_roster.roster_hash = [0; 32];
    zero_roster.adaptive_dkg.session.roster_hash = [0; 32];
    let zero_roster_binding = GlobalThresholdBeaconSessionBindingV1 {
        roster_hash: [0; 32],
        ..expected
    };
    assert_eq!(
        validate_global_threshold_beacon_session_v1(
            &(zero_roster),
            &zero_roster_binding,
            &super::fixtures::fixture_budget()
        )
        .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::InvalidDkgSession)
    );

    let mut wrong_transcript = record.clone();
    wrong_transcript.transcript_hash[0] ^= 1;
    assert_eq!(
        validate_global_threshold_beacon_session_v1(
            &(wrong_transcript),
            &expected,
            &super::fixtures::fixture_budget()
        )
        .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::TranscriptMismatch)
    );

    let mut malformed_key = record;
    malformed_key.group_public_key = [0; 96];
    assert_eq!(
        validate_global_threshold_beacon_session_v1(
            &(malformed_key),
            &expected,
            &super::fixtures::fixture_budget()
        )
        .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::ThresholdBls(
            ThresholdBlsError::InvalidPublicKey
        ))
    );
}

#[test]
fn threshold_beacon_and_tle_sessions_are_type_and_domain_separated() {
    let (session, _) = validated_threshold_session();
    let record = session.record();
    let beacon = ThresholdBlsSession::<BeaconPurpose>::new(
        *record.network_id.as_bytes(),
        record.session_id,
        record.roster_hash,
        record.committee_size,
        record.threshold,
    )
    .expect("beacon session");
    let tle = ThresholdBlsSession::<TleReleasePurpose>::new(
        *record.network_id.as_bytes(),
        record.session_id,
        record.roster_hash,
        record.committee_size,
        record.threshold,
    )
    .expect("TLE session");
    assert_ne!(
        beacon
            .signing_message(b"same payload")
            .expect("beacon message"),
        tle.signing_message(b"same payload").expect("TLE message")
    );
}

#[test]
fn threshold_beacon_pulse_payload_binds_every_consensus_field() {
    let (session, _) = validated_threshold_session();
    let (pulse, _, _) = pulse_fixture(&session);
    let baseline = global_threshold_beacon_pulse_payload_v1(&pulse);

    let mut mutations = Vec::new();
    let mut changed = pulse.clone();
    changed.network_id = beacon_fixture_network_id(0x82);
    mutations.push(changed);
    let mut changed = pulse.clone();
    changed.session_id[0] ^= 1;
    mutations.push(changed);
    let mut changed = pulse.clone();
    changed.roster_hash[0] ^= 1;
    mutations.push(changed);
    let mut changed = pulse.clone();
    changed.transcript_hash[0] ^= 1;
    mutations.push(changed);
    let mut changed = pulse;
    changed.context.instance[0] ^= 1;
    mutations.push(changed);
    let mut changed = pulse;
    changed.context.epoch += 1;
    mutations.push(changed);
    let mut changed = pulse;
    changed.context.epoch_context_id[0] ^= 1;
    mutations.push(changed);
    let mut changed = pulse;
    changed.context.parent_consensus_hash[0] ^= 1;
    mutations.push(changed);
    let mut changed = pulse;
    changed.context.parent_result[0] ^= 1;
    mutations.push(changed);
    let mut changed = pulse.clone();
    changed.height += 1;
    mutations.push(changed);
    let mut changed = pulse.clone();
    changed.round += 1;
    mutations.push(changed);
    let mut changed = pulse;
    changed.finalized_chain_anchor.block_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x89; 32]));
    mutations.push(changed);

    for mutation in mutations {
        assert_ne!(
            global_threshold_beacon_pulse_payload_v1(&mutation),
            baseline
        );
    }
}

#[test]
fn threshold_beacon_partials_and_final_signatures_require_external_native_context() {
    let (fixture, pulse, _cursor, anchor) = signed_pulse_fixture();
    let original = pulse.context;
    let partial = pulse_partial_signatures(&fixture, &pulse, [0xA9; 32])[0];
    let mut exact = GlobalThresholdBeaconPulseAggregatorV1::new(
        fixture.session.clone(),
        pulse.height,
        anchor,
        original,
    )
    .unwrap();
    assert_eq!(exact.accept_partial(partial), Ok(true));
    let frame = norito::encode_canonical(&pulse).unwrap();
    for field in 0..5 {
        let mut changed = original;
        match field {
            0 => changed.instance[0] ^= 1,
            1 => changed.epoch += 1,
            2 => changed.epoch_context_id[0] ^= 1,
            3 => changed.parent_consensus_hash[0] ^= 1,
            _ => changed.parent_result[0] ^= 1,
        }
        let mut other = GlobalThresholdBeaconPulseAggregatorV1::new(
            fixture.session.clone(),
            pulse.height,
            anchor,
            changed,
        )
        .unwrap();
        assert!(
            other.accept_partial(partial).is_err(),
            "partial context field {field}"
        );
        assert!(
            verify_finalized_global_threshold_beacon_pulse_v1(
                &fixture.session,
                &pulse,
                anchor,
                &changed,
            )
            .is_err(),
            "external context field {field}"
        );
        assert!(
            decode_finalized_global_threshold_beacon_pulse_v1(
                &frame,
                &fixture.session,
                anchor,
                &changed,
            )
            .is_err(),
            "decoded context field {field}"
        );
        let mut relabeled = pulse;
        relabeled.context = changed;
        assert!(
            verify_finalized_global_threshold_beacon_pulse_v1(
                &fixture.session,
                &relabeled,
                anchor,
                &changed,
            )
            .is_err(),
            "signature cannot be relabeled to context field {field}"
        );
    }
    assert!(
        verify_finalized_global_threshold_beacon_pulse_v1(
            &fixture.session,
            &pulse,
            anchor,
            &original,
        )
        .is_ok()
    );
}

#[test]
fn threshold_beacon_accepts_one_adaptive_final_signature_and_seed() {
    let (fixture, pulse, _cursor, anchor) = signed_pulse_fixture();

    assert_eq!(
        verify_finalized_global_threshold_beacon_pulse_v1(
            &fixture.session,
            &pulse,
            anchor,
            &pulse.context,
        ),
        Ok(GlobalThresholdBeaconPulseLinkV1 {
            pulse_id: pulse.pulse_id,
            seed: pulse.seed,
            height: pulse.height,
            round: pulse.round,
        })
    );
}

#[test]
fn first_finalized_pulse_initializes_an_empty_ingestion_cursor() {
    let (fixture, pulse, _origin, anchor) = signed_pulse_fixture();
    let mut key_record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
        fixture.session.record().clone(),
        &super::fixtures::fixture_budget(),
    )
    .expect("valid finalized beacon key");
    key_record
        .activate(
            key_record.session.adaptive_dkg.finalized_at_height,
            &super::fixtures::fixture_budget(),
        )
        .map_err(invalid_session)
        .expect("activate finalized beacon key");
    let world = World::new();
    {
        let mut block = world.block();
        {
            let mut transaction =
                block.transaction_without_telemetry(RuntimeLaneConfig::default(), 0);
            transaction.global_beacon_key_sessions.insert(
                pulse.session_id,
                RetainedFinalizedGlobalThresholdBeaconSessionV1::admit(
                    &key_record,
                    &super::fixtures::fixture_budget(),
                )
                .unwrap(),
            );
            transaction
                .global_beacon_active_session
                .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, pulse.session_id);
            assert_eq!(
                transaction.verify_and_advance_global_beacon_pulse(
                    &fixture.session,
                    pulse,
                    anchor,
                    &crate::beacon::pulse_context_fixture_v1(),
                ),
                Ok(GlobalThresholdBeaconPulseLinkV1 {
                    pulse_id: pulse.pulse_id,
                    seed: pulse.seed,
                    height: pulse.height,
                    round: pulse.round,
                })
            );
            transaction.apply();
        }
        block.commit();
    }
    assert_eq!(
        verified_latest_global_threshold_beacon_pulse_v1(
            &world.view(),
            &pulse.network_id,
            pulse.height,
        ),
        Ok(pulse),
        "the first certified pulse must create the authoritative cursor without a test-seeded origin"
    );
    let world_view = world.view();
    assert_eq!(
        world_view.global_beacon_pulse_at_slot(&pulse.network_id, pulse.height),
        Some(&pulse),
        "the authoritative insertion corridor must update the exact slot index atomically"
    );
    drop(world_view);
    assert_eq!(
        verified_global_threshold_beacon_pulse_at_or_before_v1(
            &world.view(),
            &pulse.network_id,
            pulse.height,
        ),
        Ok(pulse)
    );
    assert_eq!(
        verified_global_threshold_beacon_pulse_at_or_before_v1(
            &world.view(),
            &pulse.network_id,
            pulse.height - 1,
        ),
        Err(GlobalThresholdBeaconError::InvalidPulseHistory)
    );

    let mut conflicting_slot = pulse;
    conflicting_slot.pulse_id[0] ^= 1;
    let mut block = world.block();
    let mut transaction = block.transaction_without_telemetry(RuntimeLaneConfig::default(), 0);
    assert_eq!(
        transaction.verify_and_advance_global_beacon_pulse(
            &fixture.session,
            conflicting_slot,
            anchor,
            &crate::beacon::pulse_context_fixture_v1(),
        ),
        Err(GlobalThresholdBeaconError::ReusedPulse),
        "a distinct pulse id cannot claim an already indexed logical-beacon-height slot"
    );
}

#[test]
fn consensus_pulse_at_an_awaited_parliament_slot_is_stored_after_transcript_restart_roundtrip() {
    let (fixture, pulse, _origin, anchor) = signed_pulse_fixture();
    let roster = live_producer_keys()
        .into_iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let (governance_attempt_id, _, attempt) =
        pending_batched_sortition_attempt(&pulse.network_id, &roster, pulse.height);
    let awaiting_election_id =
        BodyElectionAttemptId::derive_v1(governance_attempt_id, ParliamentBody::RulesCommittee, 0);
    let logical_session = BeaconSessionId::for_network_v1(&pulse.network_id);
    assert!(attempt.requires_beacon_pulse_at(logical_session, pulse.height));

    // The pending wait survives both codecs unchanged and restores at any later height.
    let encoded = norito::json::to_json(&attempt)
        .expect("serialize the pending Parliament transcript for restart");
    let restored_attempt: ParliamentAttemptStateV1 =
        norito::json::from_str(&encoded).expect("restore the pending Parliament transcript");
    assert_eq!(restored_attempt, attempt);
    let framed = norito::to_bytes(&attempt).expect("encode the pending Parliament transcript");
    let decoded: ParliamentAttemptStateV1 =
        norito::decode_from_bytes(&framed).expect("decode the pending Parliament transcript");
    assert_eq!(decoded, attempt);
    restored_attempt
        .validate()
        .expect("a restored pulse wait remains canonical");
    restored_attempt
        .validate_restored_height_v1(pulse.height + 1_000_000)
        .expect("a slot far below the restored height is still a valid wait");
    assert!(restored_attempt.requires_beacon_pulse_at(logical_session, pulse.height));
    assert!(
        restored_attempt
            .unavailable_release_pulse_slots_v1()
            .is_empty()
    );

    let mut key_record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
        fixture.session.record().clone(),
        &super::fixtures::fixture_budget(),
    )
    .expect("valid finalized beacon key");
    key_record
        .activate(
            key_record.session.adaptive_dkg.finalized_at_height,
            &super::fixtures::fixture_budget(),
        )
        .map_err(invalid_session)
        .expect("activate finalized beacon key");
    let world = World::new();
    let mut block = world.block();
    let mut transaction = block.transaction_without_telemetry(RuntimeLaneConfig::default(), 0);
    transaction.global_beacon_key_sessions.insert(
        pulse.session_id,
        RetainedFinalizedGlobalThresholdBeaconSessionV1::admit(
            &key_record,
            &super::fixtures::fixture_budget(),
        )
        .unwrap(),
    );
    transaction
        .global_beacon_active_session
        .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, pulse.session_id);
    transaction
        .put_parliament_attempt(restored_attempt)
        .expect("index the restored pulse wait");
    assert_eq!(
        transaction.verify_and_advance_global_beacon_pulse(
            &fixture.session,
            pulse,
            anchor,
            &crate::beacon::pulse_context_fixture_v1(),
        ),
        Ok(GlobalThresholdBeaconPulseLinkV1 {
            pulse_id: pulse.pulse_id,
            seed: pulse.seed,
            height: pulse.height,
            round: pulse.round,
        }),
        "no Parliament state may veto a consensus pulse at a slot an election names"
    );
    let stored = transaction
        .parliament_attempts
        .get(&governance_attempt_id)
        .expect("stored attempt");
    let election = stored
        .election(&awaiting_election_id)
        .expect("stored election");
    assert_eq!(
        election.attempt().status,
        iroha_data_model::governance::types::BodyElectionAttemptStatusV1::AwaitingPulse,
        "storing the pulse does not move the election: only consumption draws"
    );
    assert_eq!(election.attempt().request.pulse_height, pulse.height);
    assert!(
        transaction
            .parliament_required_beacon_pulse_slots
            .get(&(logical_session, pulse.height))
            .is_some_and(|attempts| attempts.contains(&governance_attempt_id)),
        "the governance-local index keeps the awaited slot until the pulse is consumed"
    );
}

#[test]
fn threshold_beacon_slot_is_identical_when_prior_unrelated_height_is_persisted_or_omitted() {
    let budget = super::fixtures::fixture_budget();
    let dkg_session = super::fixtures::adaptive_dkg_session_fixture();
    let fixture = super::fixtures::adaptive_beacon_fixture_for_session_and_keys(
        dkg_session,
        &super::fixtures::adaptive_fixture_signing_keys(dkg_session.committee_size),
        &budget,
    );
    let (template, origin, target_anchor) = pulse_fixture(&fixture.session);
    let finalize_slot =
        |height: u64, anchor: GlobalThresholdBeaconChainAnchorV1, proof_seed: [u8; 32]| {
            let mut unsigned = template;
            unsigned.height = height;
            unsigned.finalized_chain_anchor = anchor;
            let partials = pulse_partial_signatures(&fixture, &unsigned, proof_seed);
            let mut aggregator = GlobalThresholdBeaconPulseAggregatorV1::new(
                fixture.session.clone(),
                height,
                anchor,
                template.context,
            )
            .expect("open unchained slot aggregator");
            for partial in partials.into_iter().take(usize::from(
                fixture.session.transcript().session().threshold(),
            )) {
                aggregator
                    .accept_partial(partial)
                    .expect("accept exact slot partial");
            }
            aggregator.finalize().expect("finalize exact slot")
        };

    let target_without_prior = finalize_slot(41, target_anchor, [0x31; 32]);
    let prior_anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: 39,
        block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x87; 32])),
    };
    let prior = finalize_slot(40, prior_anchor, [0x32; 32]);
    let mut key_record = RetainedFinalizedGlobalThresholdBeaconSessionV1 {
        session: fixture.session.clone(),
        activated_at_height: None,
        retired_at_height: None,
    };
    assert!(key_record.session.belongs_to(&budget));
    assert!(key_record.session.ptr_eq(&fixture.session));
    key_record
        .activate(key_record.session.adaptive_dkg.finalized_at_height)
        .expect("activate finalized key");
    let world = World::new();
    {
        let mut block = world.block();
        {
            let mut transaction =
                block.transaction_without_telemetry(RuntimeLaneConfig::default(), 0);
            transaction
                .global_beacon_key_sessions
                .insert(prior.session_id, key_record);
            transaction
                .global_beacon_active_session
                .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, prior.session_id);
            transaction
                .global_beacon_latest_pulse
                .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, origin);
            transaction
                .verify_and_advance_global_beacon_pulse(
                    &fixture.session,
                    prior,
                    prior_anchor,
                    &crate::beacon::pulse_context_fixture_v1(),
                )
                .expect("persist prior unrelated pulse");
            transaction.apply();
        }
        block.commit();
    }
    assert_eq!(
        verified_latest_global_threshold_beacon_pulse_v1(
            &world.view(),
            &prior.network_id,
            prior.height,
        ),
        Ok(prior)
    );

    let target_after_persisted_prior = finalize_slot(41, target_anchor, [0x33; 32]);
    assert_eq!(target_after_persisted_prior, target_without_prior);
    assert_eq!(
        target_after_persisted_prior.seed, target_without_prior.seed,
        "an unrelated earlier pulse must not influence the later slot seed"
    );
}

#[test]
fn parliament_seed_reverifies_valid_and_rejects_tampered_persisted_pulse() {
    let (fixture, pulse, _origin, _anchor) = signed_pulse_fixture();
    let mut key_record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
        fixture.session.record().clone(),
        &super::fixtures::fixture_budget(),
    )
    .expect("valid finalized key");
    key_record
        .activate(
            key_record.session.adaptive_dkg.finalized_at_height,
            &super::fixtures::fixture_budget(),
        )
        .map_err(invalid_session)
        .expect("activate finalized key");
    let link = GlobalThresholdBeaconPulseLinkV1 {
        pulse_id: pulse.pulse_id,
        seed: pulse.seed,
        height: pulse.height,
        round: pulse.round,
    };
    let persisted_world = |stored_pulse: FinalizedGlobalThresholdBeaconPulseV1| {
        let world = World::new();
        {
            let mut block = world.block();
            block.global_beacon_key_sessions.insert(
                pulse.session_id,
                RetainedFinalizedGlobalThresholdBeaconSessionV1::admit(
                    &key_record,
                    &super::fixtures::fixture_budget(),
                )
                .unwrap(),
            );
            block
                .global_beacon_active_session
                .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, pulse.session_id);
            block
                .global_beacon_pulses
                .insert(stored_pulse.pulse_id, stored_pulse);
            block.global_beacon_pulse_slots.insert(
                (
                    BeaconSessionId::for_network_v1(&stored_pulse.network_id),
                    stored_pulse.height,
                ),
                stored_pulse.pulse_id,
            );
            block
                .global_beacon_latest_pulse
                .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, link);
            block.commit();
        }
        world
    };

    let valid_world = persisted_world(pulse);
    assert_eq!(
        verified_persisted_global_threshold_beacon_governance_seed_v1(
            &valid_world.view(),
            &pulse.network_id,
            &pulse,
            pulse.height,
        ),
        Ok(global_threshold_beacon_governance_seed_v1(
            &pulse,
            pulse.height,
        ))
    );

    let mut tampered = pulse;
    tampered.signature[0] ^= 1;
    let tampered_world = persisted_world(tampered);
    assert!(
        verified_persisted_global_threshold_beacon_governance_seed_v1(
            &tampered_world.view(),
            &pulse.network_id,
            &tampered,
            pulse.height,
        )
        .is_err(),
        "Parliament must not derive entropy from an invalid restored pulse"
    );
}

#[test]
fn threshold_beacon_partial_reducer_is_bound_fail_closed_and_subset_invariant() {
    let fixture = adaptive_beacon_fixture();
    let (pulse, _cursor, anchor) = pulse_fixture(&fixture.session);
    let partials = pulse_partial_signatures(&fixture, &pulse, [0xA7; 32]);
    let threshold = usize::from(fixture.session.transcript().session().threshold());

    let open_reducer = || {
        GlobalThresholdBeaconPulseAggregatorV1::new(
            fixture.session.clone(),
            pulse.height,
            anchor,
            pulse.context,
        )
        .expect("open exact pulse reducer")
    };
    let mut insufficient = open_reducer();
    for partial in partials.iter().take(threshold - 1).cloned() {
        assert_eq!(insufficient.accept_partial(partial), Ok(true));
    }
    assert_eq!(
        insufficient.finalize(),
        Err(GlobalThresholdBeaconError::InsufficientPartialSignatures)
    );

    let mut low_indices = open_reducer();
    for partial in partials.iter().take(threshold).cloned() {
        assert_eq!(low_indices.accept_partial(partial), Ok(true));
    }
    assert_eq!(
        low_indices.accept_partial(partials[0]),
        Ok(false),
        "exact retransmissions must be idempotent"
    );
    let low_pulse = low_indices.finalize().expect("low-index threshold");

    let mut high_indices = open_reducer();
    for partial in partials.iter().rev().take(threshold).cloned() {
        assert_eq!(high_indices.accept_partial(partial), Ok(true));
    }
    assert_eq!(
        high_indices.finalize().expect("high-index threshold"),
        low_pulse,
        "the public pulse must not expose or depend on the reconstruction subset"
    );

    let mut wrong_session = partials[0];
    wrong_session.session_id[0] ^= 1;
    assert_eq!(
        open_reducer().accept_partial(wrong_session),
        Err(GlobalThresholdBeaconError::SessionMismatch)
    );

    let distinct_valid_proof = pulse_partial_signatures(&fixture, &pulse, [0xB8; 32])[0];
    assert_ne!(partials[0], distinct_valid_proof);
    let mut equivocating = open_reducer();
    assert_eq!(equivocating.accept_partial(partials[0]), Ok(true));
    assert_eq!(
        equivocating.accept_partial(distinct_valid_proof),
        Ok(false),
        "fresh proof randomness for the same verified share is an idempotent retry"
    );

    let mismatched_anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: pulse.height,
        block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x89; 32])),
    };
    let mut other_height = GlobalThresholdBeaconPulseAggregatorV1::new(
        fixture.session.clone(),
        pulse.height + 1,
        mismatched_anchor,
        pulse.context,
    )
    .expect("open another exact pulse round");
    assert!(matches!(
        other_height.accept_partial(partials[0]),
        Err(GlobalThresholdBeaconError::ThresholdBls(_))
    ));
}

#[test]
fn threshold_beacon_inline_reducer_rejects_invalid_share_without_losing_original_slots() {
    let fixture = adaptive_beacon_fixture();
    let (pulse, _, anchor) = pulse_fixture(&fixture.session);
    let partials = pulse_partial_signatures(&fixture, &pulse, [0xD1; 32]);
    let mut reducer = GlobalThresholdBeaconPulseAggregatorV1::new(
        fixture.session.clone(),
        pulse.height,
        anchor,
        pulse.context,
    )
    .unwrap();
    assert_eq!(reducer.verified_partial_count(), 0);
    assert_eq!(reducer.accept_partial(partials[0]), Ok(true));
    let original_slots = reducer.partials;

    // All signature/proof points remain genuine and canonically encoded, but
    // this share was not proved for seat three. HC59 must not admit it.
    let mut rebound = partials[1];
    rebound.signer_index = 3;
    assert!(matches!(
        reducer.accept_partial(rebound),
        Err(GlobalThresholdBeaconError::ThresholdBls(_))
    ));
    assert_eq!(reducer.partials, original_slots);

    // A retransmission is only idempotent after its proof has been rechecked.
    let mut forged_retry = partials[0];
    forged_retry.proof = partials[1].proof;
    assert!(matches!(
        reducer.accept_partial(forged_retry),
        Err(GlobalThresholdBeaconError::ThresholdBls(_))
    ));
    assert_eq!(reducer.partials, original_slots);
    for signer_index in [0, 5, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 + 1, u16::MAX] {
        let mut out_of_range = partials[0];
        out_of_range.signer_index = signer_index;
        assert_eq!(
            reducer.accept_partial(out_of_range),
            Err(ThresholdBlsError::InvalidParticipantIndex.into())
        );
        assert_eq!(reducer.partials, original_slots);
    }
    assert_eq!(reducer.verified_partial_count(), 1);
    assert_eq!(
        reducer.finalize(),
        Err(GlobalThresholdBeaconError::InsufficientPartialSignatures)
    );
    assert_eq!(reducer.accept_partial(partials[0]), Ok(false));
    let fresh_proof = pulse_partial_signatures(&fixture, &pulse, [0xD2; 32])[0];
    assert_ne!(fresh_proof.proof, partials[0].proof);
    assert_eq!(reducer.accept_partial(fresh_proof), Ok(false));
    assert_eq!(
        reducer.partials, original_slots,
        "a valid retransmission preserves the originally admitted proof"
    );
    assert_eq!(reducer.accept_partial(partials[1]), Ok(true));
    assert_eq!(reducer.verified_partial_count(), 2);
    reducer
        .finalize()
        .expect("original shares remain usable after rejected input");
}

#[test]
fn threshold_beacon_inline_reducer_preserves_conflicting_original_slot() {
    let fixture = adaptive_beacon_fixture();
    let (pulse, _, anchor) = pulse_fixture(&fixture.session);
    let partials = pulse_partial_signatures(&fixture, &pulse, [0xD3; 32]);
    let mut reducer = GlobalThresholdBeaconPulseAggregatorV1::new(
        fixture.session.clone(),
        pulse.height,
        anchor,
        pulse.context,
    )
    .unwrap();
    let mut another_payload = pulse;
    another_payload.height += 1;
    let other_partials = pulse_partial_signatures(&fixture, &another_payload, [0xD4; 32]);
    assert!(reducer.accept_partial(other_partials[0]).is_err());
    assert_eq!(reducer.verified_partial_count(), 0);

    // Two valid shares for one exact slot cannot disagree under the unique
    // signature construction. Corrupt an internal slot here to exercise the
    // reducer's fail-closed conflict guard without admitting an invalid proof.
    reducer.partials[0] = Some(adaptive_partial_signature_from_dto_v1(&other_partials[0]).unwrap());
    let original_slots = reducer.partials;
    assert_eq!(
        reducer.accept_partial(partials[0]),
        Err(GlobalThresholdBeaconError::PartialSignatureEquivocation)
    );
    assert_eq!(reducer.partials, original_slots);
}

#[test]
fn threshold_beacon_inline_reducer_maximum_committee_is_order_and_subset_invariant() {
    let fixture = complete_dkg_fixture(THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1);
    let (pulse, _, anchor) = pulse_fixture(&fixture.session);
    let partials = pulse_partial_signatures(&fixture, &pulse, [0xD5; 32]);
    let threshold = usize::from(fixture.session.transcript().session().threshold());
    assert_eq!(threshold, GLOBAL_BEACON_MAX_THRESHOLD);
    assert_eq!(partials.len(), GLOBAL_BEACON_PARTIAL_SLOTS);
    let open = || {
        GlobalThresholdBeaconPulseAggregatorV1::new(
            fixture.session.clone(),
            pulse.height,
            anchor,
            pulse.context,
        )
        .unwrap()
    };

    let mut high = open();
    for partial in partials.iter().rev().take(threshold - 1).copied() {
        assert_eq!(high.accept_partial(partial), Ok(true));
    }
    assert_eq!(high.verified_partial_count(), threshold - 1);
    assert_eq!(
        high.finalize(),
        Err(GlobalThresholdBeaconError::InsufficientPartialSignatures)
    );
    assert_eq!(
        high.partials.last().unwrap().unwrap().index(),
        THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1
    );
    assert_eq!(
        high.accept_partial(partials[partials.len() - threshold]),
        Ok(true)
    );
    let expected = high
        .finalize()
        .expect("maximum-index threshold reconstructs");

    let mut low = open();
    for partial in partials.iter().take(threshold).copied() {
        assert_eq!(low.accept_partial(partial), Ok(true));
    }
    assert_eq!(
        low.finalize().unwrap(),
        expected,
        "disjoint low and high subsets produce the exact same public pulse"
    );
    for partial in partials.iter().rev().copied() {
        let was_present = high.partials[usize::from(partial.signer_index - 1)].is_some();
        assert_eq!(high.accept_partial(partial), Ok(!was_present));
    }
    assert_eq!(high.verified_partial_count(), GLOBAL_BEACON_PARTIAL_SLOTS);
    assert_eq!(
        high.partials
            .iter()
            .flatten()
            .map(|partial| partial.index())
            .collect::<Vec<_>>(),
        (1..=THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1).collect::<Vec<_>>()
    );
    assert_eq!(
        high.finalize().unwrap(),
        expected,
        "reverse arrival of all seats still uses a canonical ordered threshold"
    );
    assert_eq!(
        high.finalize().unwrap(),
        expected,
        "reconstruction is repeatable without consuming or replacing original shares"
    );
}

#[test]
fn npos_successor_seed_binds_verified_pulse_and_target_epoch() {
    const BOUNDARY_HEIGHT: u64 = 42;
    const SUCCESSOR_EPOCH: u64 = 9;
    let (fixture, pulse, _cursor, anchor) = signed_pulse_fixture();
    verify_finalized_global_threshold_beacon_pulse_v1(
        &fixture.session,
        &pulse,
        anchor,
        &pulse.context,
    )
    .expect("authenticated pulse and exact chain anchor");
    let expected_seed =
        global_threshold_beacon_npos_successor_seed_v1(&pulse, BOUNDARY_HEIGHT, SUCCESSOR_EPOCH);
    assert_ne!(expected_seed, pulse.seed, "NPoS seed has its own domain");
    assert_ne!(
        expected_seed,
        global_threshold_beacon_npos_successor_seed_v1(
            &pulse,
            BOUNDARY_HEIGHT,
            SUCCESSOR_EPOCH + 1,
        )
    );
    assert_ne!(
        expected_seed,
        global_threshold_beacon_npos_successor_seed_v1(
            &pulse,
            BOUNDARY_HEIGHT + 1,
            SUCCESSOR_EPOCH,
        )
    );
    let mut foreign = pulse;
    foreign.network_id = beacon_fixture_network_id(0x82);
    assert!(
        verify_finalized_global_threshold_beacon_pulse_v1(
            &fixture.session,
            &foreign,
            anchor,
            &pulse.context,
        )
        .is_err()
    );
    let mut wrong_anchor = anchor;
    wrong_anchor.block_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xFE; 32]));
    assert!(
        verify_finalized_global_threshold_beacon_pulse_v1(
            &fixture.session,
            &pulse,
            wrong_anchor,
            &pulse.context,
        )
        .is_err()
    );
}

#[test]
fn threshold_beacon_pulse_rejects_zero_noncanonical_round_and_wrong_anchor() {
    let (session, _) = validated_threshold_session();
    let (pulse, _cursor, anchor) = pulse_fixture(&session);

    let mut zero = pulse.clone();
    zero.seed = [0; 32];
    assert_eq!(
        verify_finalized_global_threshold_beacon_pulse_v1(&session, &zero, anchor, &pulse.context,),
        Err(GlobalThresholdBeaconError::ZeroPulse)
    );

    let mut noncanonical_round = pulse;
    noncanonical_round.round = 1;
    assert_eq!(
        verify_finalized_global_threshold_beacon_pulse_v1(
            &session,
            &noncanonical_round,
            anchor,
            &pulse.context,
        ),
        Err(GlobalThresholdBeaconError::NonCanonicalRound)
    );

    let wrong_anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: anchor.height + 1,
        ..anchor
    };
    assert_eq!(
        verify_finalized_global_threshold_beacon_pulse_v1(
            &session,
            &pulse,
            wrong_anchor,
            &pulse.context,
        ),
        Err(GlobalThresholdBeaconError::FinalizedAnchorMismatch)
    );
}

#[test]
fn threshold_beacon_pulse_rejects_malformed_and_wrong_final_signatures() {
    let (session, _) = validated_threshold_session();
    let (pulse, _cursor, anchor) = pulse_fixture(&session);

    let mut malformed = pulse.clone();
    malformed.signature = [0; 48];
    assert_eq!(
        verify_finalized_global_threshold_beacon_pulse_v1(
            &session,
            &malformed,
            anchor,
            &pulse.context,
        ),
        Err(GlobalThresholdBeaconError::ThresholdBls(
            ThresholdBlsError::InvalidSignature
        ))
    );
    assert_eq!(
        verify_finalized_global_threshold_beacon_pulse_v1(&session, &pulse, anchor, &pulse.context,),
        Err(GlobalThresholdBeaconError::ThresholdBls(
            ThresholdBlsError::SignatureMismatch
        ))
    );
}

#[test]
fn shared_beacon_frame_owners_pass_the_production_session_and_pulse_boundaries() {
    use crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1 as check;
    let (fixture, pulse, _cursor, anchor) = signed_pulse_fixture();
    let session = &fixture.session;
    let record = session.record();
    let expected = GlobalThresholdBeaconSessionBindingV1 {
        network_id: record.network_id,
        session_id: record.session_id,
        roster_hash: record.roster_hash,
        transcript_hash: record.transcript_hash,
    };
    check(
        record,
        "iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1",
    );
    check(
        &pulse,
        "iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1",
    );
    let session_frame = norito::encode_canonical(record).expect("shared session frame");
    let decoded = decode_global_threshold_beacon_session_v1(
        &session_frame,
        &expected,
        &super::fixtures::fixture_budget(),
    )
    .map_err(invalid_session)
    .expect("canonical session passes production transcript validation");
    assert_eq!(decoded.record(), record);
    let pulse_frame = norito::encode_canonical(&pulse).expect("shared pulse frame");
    let link = decode_finalized_global_threshold_beacon_pulse_v1(
        &pulse_frame,
        session,
        anchor,
        &pulse.context,
    )
    .expect("canonical pulse passes production signature validation");
    assert_eq!(link.height, pulse.height);
    assert_eq!(link.pulse_id, pulse.pulse_id);
    assert!(matches!(
        decode_global_threshold_beacon_session_v1(
            &pulse_frame,
            &expected,
            &super::fixtures::fixture_budget()
        )
        .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::InvalidEncoding)
    ));
    assert!(matches!(
        decode_finalized_global_threshold_beacon_pulse_v1(
            &session_frame,
            session,
            anchor,
            &pulse.context,
        ),
        Err(GlobalThresholdBeaconError::InvalidEncoding)
    ));
    assert!(
        decode_global_threshold_beacon_session_v1(
            &session_frame[..session_frame.len() - 1],
            &expected,
            &super::fixtures::fixture_budget()
        )
        .map_err(invalid_session)
        .is_err()
    );
    assert!(
        decode_finalized_global_threshold_beacon_pulse_v1(
            &pulse_frame[..pulse_frame.len() - 1],
            session,
            anchor,
            &pulse.context,
        )
        .is_err()
    );
    let mut substituted = pulse;
    substituted.seed[0] ^= 1;
    let altered =
        norito::encode_canonical(&substituted).expect("encode altered pulse with valid frame");
    assert!(
        decode_finalized_global_threshold_beacon_pulse_v1(
            &altered,
            session,
            anchor,
            &pulse.context,
        )
        .is_err()
    );
}
#[test]
fn threshold_beacon_canonical_decoders_reject_trailing_wire_data() {
    let (session, expected) = validated_threshold_session();
    let mut encoded_session = norito::to_bytes(session.record()).expect("encode session");
    encoded_session.push(0);
    assert!(matches!(
        decode_global_threshold_beacon_session_v1(
            &encoded_session,
            &expected,
            &super::fixtures::fixture_budget()
        )
        .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::InvalidEncoding
            | GlobalThresholdBeaconError::NonCanonicalEncoding)
    ));

    let (pulse, _cursor, anchor) = pulse_fixture(&session);
    let mut encoded_pulse = norito::to_bytes(&pulse).expect("encode pulse");
    encoded_pulse.push(0);
    assert!(matches!(
        decode_finalized_global_threshold_beacon_pulse_v1(
            &encoded_pulse,
            &session,
            anchor,
            &pulse.context,
        ),
        Err(GlobalThresholdBeaconError::InvalidEncoding
            | GlobalThresholdBeaconError::NonCanonicalEncoding)
    ));
}

#[test]
fn session_decoder_preserves_actual_local_scope_without_invalidity_or_fabricated_pool() {
    let (session, binding) = validated_threshold_session();
    let encoded = norito::to_bytes(session.record()).unwrap();
    let original_bytes = encoded.as_ptr();
    let pool = super::fixtures::fixture_budget();
    let failure = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 256),
        || {
            let error = decode_global_threshold_beacon_session_v1(&encoded, &binding, &pool)
                .expect_err("actual inherited decoder allocation ceiling");
            let GlobalThresholdBeaconSessionError::DecodeResource(original) = &error else {
                panic!("a local decoder refusal cannot reject original canonical bytes: {error:?}")
            };
            assert!(matches!(
                original.decode_resource_error(),
                Some(norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
            ));
            assert!(
                norito::core::decode_error_matches_active_limits(original),
                "the original error retains its actual surviving decoder scope"
            );
            assert_eq!(
                pool.reserved_bytes(),
                0,
                "raw decode refused before graph admission"
            );
            error
        },
    );
    let crate::execution_attempt::ExecutionAttemptError::Deferred(local) =
        failure.into_execution_attempt()
    else {
        panic!("decoder capacity is never a completed rejection")
    };
    assert_eq!(
        local.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    );
    assert!(
        local.allocation_refusal().is_none(),
        "a decoder scope does not own an allocation-pool release"
    );
    assert!(matches!(
        decode_global_threshold_beacon_session_v1(&[], &binding, &pool),
        Err(GlobalThresholdBeaconSessionError::Invalid(
            GlobalThresholdBeaconError::InvalidEncoding
        ))
    ));
    let retried = decode_global_threshold_beacon_session_v1(&encoded, &binding, &pool).unwrap();
    assert!(retried.belongs_to(&pool));
    assert_eq!(retried.record(), session.record());
    assert_eq!(norito::to_bytes(&retried).unwrap(), encoded);
    assert_eq!(encoded.as_ptr(), original_bytes);
    drop(retried);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn finalized_session_retains_authenticated_transcript_and_checks_lifecycle() {
    let (validated, _) = validated_threshold_session();
    let budget = super::fixtures::fixture_budget();
    let record = FinalizedGlobalThresholdBeaconKeySessionRecordV1 {
        session: validated.record().clone(),
        activated_at_height: None,
        retired_at_height: None,
    };
    let retained =
        RetainedFinalizedGlobalThresholdBeaconSessionV1::admit(&record, &budget).unwrap();
    assert_eq!(retained.session.record(), validated.record());
    assert!(retained.session.belongs_to(&budget));
    assert!(retained.clone().session.ptr_eq(&retained.session));
    assert_eq!(record.validate(&budget).map_err(invalid_session), Ok(()));
    assert_eq!(retained.validate(), Ok(()));

    let mut invalid = record.clone();
    invalid.retired_at_height = Some(record.session.adaptive_dkg.finalized_at_height);
    assert_eq!(
        RetainedFinalizedGlobalThresholdBeaconSessionV1::admit(&invalid, &budget)
            .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::InvalidKeyLifecycle)
    );
    assert_eq!(
        invalid.validate(&budget).map_err(invalid_session),
        Err(GlobalThresholdBeaconError::InvalidKeyLifecycle)
    );
    invalid.session.group_public_key = [0; 96];
    assert_eq!(
        RetainedFinalizedGlobalThresholdBeaconSessionV1::admit(&invalid, &budget)
            .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::ThresholdBls(
            ThresholdBlsError::InvalidPublicKey
        ))
    );
    assert_eq!(
        invalid.validate(&budget).map_err(invalid_session),
        Err(GlobalThresholdBeaconError::ThresholdBls(
            ThresholdBlsError::InvalidPublicKey
        ))
    );
}

#[test]
fn validated_session_binding_checks_match_admission_error_order() {
    let (session, expected) = validated_threshold_session();
    let budget = super::fixtures::fixture_budget();
    assert_eq!(session.check_binding(&expected), Ok(()));
    let mut wrong = expected;
    wrong.network_id = beacon_fixture_network_id(0x82);
    wrong.session_id[0] ^= 1;
    wrong.roster_hash[0] ^= 1;
    wrong.transcript_hash[0] ^= 1;
    for error in [
        GlobalThresholdBeaconError::NetworkMismatch,
        GlobalThresholdBeaconError::SessionMismatch,
        GlobalThresholdBeaconError::RosterMismatch,
        GlobalThresholdBeaconError::TranscriptMismatch,
    ] {
        assert_eq!(session.check_binding(&wrong), Err(error));
        assert_eq!(
            validate_global_threshold_beacon_session_v1(session.record(), &wrong, &budget)
                .map_err(invalid_session),
            Err(error)
        );
        assert_eq!(budget.reserved_bytes(), 0);
        match error {
            GlobalThresholdBeaconError::NetworkMismatch => wrong.network_id = expected.network_id,
            GlobalThresholdBeaconError::SessionMismatch => wrong.session_id = expected.session_id,
            GlobalThresholdBeaconError::RosterMismatch => wrong.roster_hash = expected.roster_hash,
            GlobalThresholdBeaconError::TranscriptMismatch => {
                wrong.transcript_hash = expected.transcript_hash
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(session.check_binding(&wrong), Ok(()));
    let mut unsupported = session.record().clone();
    unsupported.version = 0;
    wrong.network_id = beacon_fixture_network_id(0x82);
    assert_eq!(
        validate_global_threshold_beacon_session_v1(&unsupported, &wrong, &budget)
            .map_err(invalid_session),
        Err(GlobalThresholdBeaconError::UnsupportedVersion { actual: 0 })
    );
    assert_eq!(budget.reserved_bytes(), 0);
}
