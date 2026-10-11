//! Genuine same-roster DKG transcripts cannot substitute another signing generation.

use super::*;

fn session_for_generation(
    authority: &ValidatorGenerationV1,
    generation: u64,
) -> (RetainedFinalizedGlobalThresholdBeaconSessionV1, Vec<PeerId>) {
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let peers = authority.validators.iter().cloned().collect::<Vec<_>>();
    let session_id = *Hash::new_from_chunks(&[
        b"committee-generation-binding-test",
        &generation.to_le_bytes(),
    ])
    .as_ref();
    let (session, _) = prepared_session_and_signers_fixture_v1(
        GlobalThresholdBeaconDkgSessionV1 {
            version: 1,
            network_id: authority.network_id,
            session_id,
            attempt_id: session_id,
            authority_generation: generation,
            roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&peers),
            committee_size: peers.len() as u16,
            threshold: ((peers.len() - 1) / 3 + 1) as u16,
            start_height: 1,
            commitments_end_height: 2,
            deliveries_end_height: 3,
            acceptances_end_height: 4,
        },
        &budget,
    );
    let record = RetainedFinalizedGlobalThresholdBeaconSessionV1 {
        session,
        activated_at_height: None,
        retired_at_height: None,
    };
    (record, peers)
}

#[test]
fn committee_bootstrap_rejects_genuine_dkg_from_another_generation() {
    let fixture = fixture(4);
    let genesis = ValidatorEpochAuthorizationV1::genesis(&fixture.incumbent, 10).unwrap();
    let world = World::new();
    for generation in [0, 1] {
        let (record, peers) = session_for_generation(&fixture.incumbent, generation);
        let result = validate_beacon_preparation(
            &world.view(),
            4,
            &fixture.incumbent,
            &genesis,
            &record,
            &peers,
        );
        if generation == fixture.incumbent.generation {
            assert_eq!(result, Ok(true));
        } else {
            assert_eq!(
                result,
                Err("bootstrap beacon differs from the genesis signing generation".to_owned()),
                "the same roster's valid generation-one transcript cannot bootstrap generation zero"
            );
        }
        assert!(world.view().active_global_beacon_key_session().is_none());
        assert!(
            world
                .view()
                .global_beacon_key_sessions()
                .iter()
                .next()
                .is_none()
        );
    }
}

#[test]
fn committee_restore_rejects_genuine_dkg_from_another_generation() {
    let fixture = fixture(4);
    let genesis = ValidatorEpochAuthorizationV1::genesis(&fixture.incumbent, 10).unwrap();
    for generation in [0, 1] {
        let (mut record, _) = session_for_generation(&fixture.incumbent, generation);
        record.activate(5).unwrap();
        let binding = InstalledBeaconEpochBindingV1 {
            session_id: record.session.session_id,
            transcript_hash: record.session.transcript_hash,
        };
        let mut world = World::new();
        world
            .global_beacon_key_sessions
            .insert(binding.session_id, record);
        world
            .global_beacon_active_session
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, binding.session_id);
        let retained = successor_authorization(
            &genesis,
            &fixture.incumbent,
            20,
            BeaconEpochBindingV1::Installed(binding),
            ValidatorEpochDecisionV1::Retain,
            [0; 32],
        );
        for (authorization, cut) in [(genesis, 4), (retained, 19)] {
            let result =
                validate_current_beacon(&world.view(), &fixture.incumbent, &authorization, cut);
            if generation == fixture.incumbent.generation {
                assert_eq!(result, Ok(()));
            } else {
                assert_eq!(
                    result,
                    Err("active beacon differs from the authorized signing generation".to_owned()),
                    "bootstrap and installed retention both require the exact DKG generation"
                );
            }
        }
    }
}
