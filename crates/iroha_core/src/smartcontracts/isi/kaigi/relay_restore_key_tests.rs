//! Restore checks for exact active Kaigi relay descriptors.

use super::*;
use crate::state::World;
use iroha_data_model::{
    asset::AssetDefinition,
    kaigi::{KaigiRelayHop, NewKaigi},
    prelude::*,
};
use iroha_test_samples::{ALICE_ID, gen_account_in};
use std::str::FromStr;

fn retained_route_world() -> (World, DomainId, KaigiId, KaigiRelayManifest, AccountId) {
    let domain_id = DomainId::try_new("kaigi-route-restore", "universal").expect("domain ID");
    let (host, _) = gen_account_in("kaigi-route-restore");
    let call = KaigiId::new(
        domain_id.clone(),
        Name::from_str("route-restore").expect("call name"),
    );
    let manifest = KaigiRelayManifest {
        hops: (0..3)
            .map(|index| {
                let (relay_id, _) = gen_account_in("kaigi-route-restore");
                KaigiRelayHop {
                    relay_id,
                    hpke_public_key: vec![u8::try_from(index + 1).expect("bounded key byte")],
                    weight: 1,
                }
            })
            .collect(),
        expiry_ms: 100,
    };
    let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
    template.relay_manifest = Some(manifest.clone());
    let record = KaigiRecord::from_new(&template, 0);
    let mut domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    domain.metadata_mut().insert(
        kaigi_metadata_key(&call.call_name).expect("call metadata key"),
        Json::try_new(record).expect("serialize active call"),
    );
    for hop in &manifest.hops {
        domain.metadata_mut().insert(
            kaigi_relay_metadata_key(&hop.relay_id).expect("relay metadata key"),
            Json::try_new(KaigiRelayRegistration {
                relay_id: hop.relay_id.clone(),
                hpke_public_key: hop.hpke_public_key.clone(),
                bandwidth_class: 1,
            })
            .expect("serialize relay descriptor"),
        );
    }
    let accounts = std::iter::once(host.clone())
        .chain(manifest.hops.iter().map(|hop| hop.relay_id.clone()))
        .map(|account| Account::new(account).build(&ALICE_ID));
    let world = World::with([domain], accounts, std::iter::empty::<AssetDefinition>());
    (world, domain_id, call, manifest, host)
}

#[test]
fn valid_active_manifest_rebuilds_and_validates_exact_registered_keys() {
    let (mut world, _, _, manifest, _) = retained_route_world();
    rebuild_kaigi_account_dependencies(&mut world).expect("rebuild valid retained route");
    validate_rebuilt_kaigi_account_dependencies_at(&world.view(), Some(100))
        .expect("valid retained route survives restart validation");
    for hop in &manifest.hops {
        assert!(
            world
                .kaigi_account_dependencies
                .view()
                .get(&hop.relay_id)
                .is_some()
        );
    }
}

#[test]
fn restore_rejects_missing_or_key_mismatched_active_relay_descriptor_without_rewriting_state() {
    for missing in [false, true] {
        let (mut world, home, _, manifest, _) = retained_route_world();
        let hop = &manifest.hops[0];
        let key = kaigi_relay_metadata_key(&hop.relay_id).expect("relay metadata key");
        {
            let mut domains = world.domains.block();
            let home_domain = domains.get_mut(&home).expect("relay home domain");
            if missing {
                home_domain.metadata_mut().remove(&key);
            } else {
                home_domain.metadata_mut().insert(
                    key,
                    Json::try_new(KaigiRelayRegistration {
                        relay_id: hop.relay_id.clone(),
                        hpke_public_key: vec![0xAA],
                        bandwidth_class: 1,
                    })
                    .expect("serialize stale registered key"),
                );
            }
            domains.commit();
        }
        let authoritative_before =
            norito::json::to_json(&world.domains).expect("serialize authoritative domain layers");
        let error = rebuild_kaigi_account_dependencies(&mut world)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("active manifest must retain a matching registered descriptor");
        let expected = if missing {
            "has no registered descriptor"
        } else {
            "HPKE key differs"
        };
        assert!(
            error.contains(expected),
            "unexpected restore error: {error}"
        );
        assert_eq!(
            norito::json::to_json(&world.domains).expect("serialize unchanged domain layers"),
            authoritative_before,
            "failed rebuild must leave authoritative domain history unchanged"
        );
    }
}

#[test]
fn ended_call_may_retain_historical_manifest_after_relay_retirement() {
    let (mut world, home, call, manifest, _) = retained_route_world();
    let record_key = kaigi_metadata_key(&call.call_name).expect("call metadata key");
    let retired = &manifest.hops[0];
    let relay_key = kaigi_relay_metadata_key(&retired.relay_id).expect("relay metadata key");
    {
        let mut domains = world.domains.block();
        let home_domain = domains.get_mut(&home).expect("call and relay home domain");
        let value = home_domain
            .metadata_mut()
            .remove(&record_key)
            .expect("active call record");
        let mut record: KaigiRecord = value
            .try_into_any_norito()
            .expect("decode active call record");
        record.status = KaigiStatus::Ended;
        record.ended_at_ms = Some(0);
        home_domain.metadata_mut().insert(
            record_key,
            Json::try_new(record).expect("serialize ended call record"),
        );
        home_domain.metadata_mut().remove(&relay_key);
        domains.commit();
    }
    rebuild_kaigi_account_dependencies(&mut world)
        .expect("ended call's historical route permits registered relay retirement");
    validate_rebuilt_kaigi_account_dependencies_at(&world.view(), Some(100))
        .expect("ended historical route survives restart validation");
}

#[test]
fn restore_accepts_feedback_with_a_retained_source_call_through_its_end() {
    let (mut world, home, call, manifest, host) = retained_route_world();
    let relay_id = manifest.hops[0].relay_id.clone();
    let feedback_key = kaigi_relay_feedback_key(&relay_id).expect("feedback metadata key");
    {
        let mut domains = world.domains.block();
        domains
            .get_mut(&home)
            .expect("relay home domain")
            .metadata_mut()
            .insert(
                feedback_key,
                Json::try_new(KaigiRelayFeedback {
                    relay_id,
                    call: call.clone(),
                    reported_by: host,
                    status: KaigiRelayHealthStatus::Healthy,
                    reported_at_ms: 10,
                    notes: None,
                })
                .expect("serialize authenticated relay observation"),
            );
        domains.commit();
    }
    rebuild_kaigi_account_dependencies_at(&mut world, Some(10))
        .expect("active call feedback remains restorable");
    validate_rebuilt_kaigi_account_dependencies_at(&world.view(), Some(10))
        .expect("active call source matches retained metadata");

    let record_key = kaigi_metadata_key(&call.call_name).expect("call metadata key");
    {
        let mut domains = world.domains.block();
        let domain = domains.get_mut(&home).expect("call home domain");
        let value = domain
            .metadata_mut()
            .remove(&record_key)
            .expect("active call metadata");
        let mut record: KaigiRecord = value.try_into_any_norito().expect("decode retained call");
        record.status = KaigiStatus::Ended;
        record.ended_at_ms = Some(10);
        domain.metadata_mut().insert(
            record_key,
            Json::try_new(record).expect("serialize ended call"),
        );
        domains.commit();
    }
    rebuild_kaigi_account_dependencies_at(&mut world, Some(10))
        .expect("feedback at the finalized end remains restorable");
    validate_rebuilt_kaigi_account_dependencies_at(&world.view(), Some(10))
        .expect("ended call source matches retained metadata");
}

#[test]
fn restore_rejects_orphan_precreation_and_post_end_feedback_without_rewriting_metadata() {
    for violation in ["orphan", "precreation", "post-end"] {
        let (mut world, home, call, manifest, host) = retained_route_world();
        let relay_id = manifest.hops[0].relay_id.clone();
        let mut feedback = KaigiRelayFeedback {
            relay_id: relay_id.clone(),
            call: call.clone(),
            reported_by: host,
            status: KaigiRelayHealthStatus::Degraded,
            reported_at_ms: 10,
            notes: None,
        };
        let record_key = kaigi_metadata_key(&call.call_name).expect("call metadata key");
        let feedback_key = kaigi_relay_feedback_key(&relay_id).expect("feedback metadata key");
        {
            let mut domains = world.domains.block();
            let domain = domains.get_mut(&home).expect("call and relay home domain");
            match violation {
                "orphan" => {
                    feedback.call = KaigiId::new(
                        home.clone(),
                        Name::from_str("missing-source-call").expect("missing call name"),
                    );
                }
                "precreation" | "post-end" => {
                    let value = domain
                        .metadata_mut()
                        .remove(&record_key)
                        .expect("retained call metadata");
                    let mut record: KaigiRecord =
                        value.try_into_any_norito().expect("decode retained call");
                    if violation == "precreation" {
                        record.created_at_ms = 11;
                    } else {
                        record.status = KaigiStatus::Ended;
                        record.ended_at_ms = Some(9);
                    }
                    domain.metadata_mut().insert(
                        record_key.clone(),
                        Json::try_new(record).expect("serialize retained call"),
                    );
                }
                _ => unreachable!("test cases are exhaustive"),
            }
            domain.metadata_mut().insert(
                feedback_key,
                Json::try_new(feedback).expect("serialize retained feedback"),
            );
            domains.commit();
        }
        let authoritative_before =
            norito::json::to_json(&world.domains).expect("serialize authoritative domain layers");
        let error = rebuild_kaigi_account_dependencies_at(&mut world, Some(20))
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("invalid feedback source must fail restore");
        let expected = match violation {
            "orphan" => "references missing call",
            "precreation" => "predates its creation",
            "post-end" => "later than its finalized end",
            _ => unreachable!("test cases are exhaustive"),
        };
        assert!(
            error.contains(expected),
            "unexpected restore error: {error}"
        );
        assert_eq!(
            norito::json::to_json(&world.domains).expect("serialize unchanged domain layers"),
            authoritative_before,
            "rejected feedback must not rewrite authoritative metadata"
        );
    }
}

#[test]
fn restore_rejects_orphan_feedback_in_undo_layer() {
    let (mut world, home, call, manifest, host) = retained_route_world();
    let relay_id = manifest.hops[0].relay_id.clone();
    let key = kaigi_relay_feedback_key(&relay_id).expect("feedback metadata key");
    {
        let mut domains = world.domains.block();
        domains
            .get_mut(&home)
            .expect("relay home domain")
            .metadata_mut()
            .insert(
                key.clone(),
                Json::try_new(KaigiRelayFeedback {
                    relay_id,
                    call: KaigiId::new(
                        call.domain_id,
                        Name::from_str("undo-missing-call").expect("missing call name"),
                    ),
                    reported_by: host,
                    status: KaigiRelayHealthStatus::Unavailable,
                    reported_at_ms: 10,
                    notes: None,
                })
                .expect("serialize orphan feedback"),
            );
        domains.commit();
    }
    {
        let mut domains = world.domains.block();
        domains
            .get_mut(&home)
            .expect("relay home domain")
            .metadata_mut()
            .remove(&key);
        domains.commit();
    }
    let authoritative_before =
        norito::json::to_json(&world.domains).expect("serialize authoritative domain layers");
    let error = rebuild_kaigi_account_dependencies_at(&mut world, Some(10))
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .expect_err("orphan feedback in the latest undo layer must fail restore");
    assert!(
        error.contains("references missing call"),
        "unexpected error: {error}"
    );
    assert_eq!(
        norito::json::to_json(&world.domains).expect("serialize unchanged domain layers"),
        authoritative_before,
        "rejected undo layer must not rewrite authoritative metadata"
    );
}
