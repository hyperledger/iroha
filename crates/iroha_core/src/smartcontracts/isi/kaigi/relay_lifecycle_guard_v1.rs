//! Keep live Kaigi relay routes bound to their registered HPKE keys.

use super::{
    AccountId, Error, IndexedKaigiDependency, KAIGI_DEPENDENCY_ACTIVE_CALL, StateTransaction,
    relay_error, validate_indexed_kaigi_dependency,
};
use mv::storage::StorageReadOnly;

/// Reject changing a relay's route while a live call still names its exact ID.
///
/// The reverse index narrows the search to this relay, but each indexed call is
/// decoded and checked against authoritative metadata before it can block the
/// operation. An invalid locator is an invariant failure, not permission to
/// strand a route.
pub(super) fn ensure_no_active_manifest_reference(
    state_transaction: &StateTransaction<'_, '_>,
    relay_id: &AccountId,
    operation: &str,
) -> Result<(), Error> {
    let Some(dependencies) = state_transaction
        .world
        .kaigi_account_dependencies
        .get(relay_id)
    else {
        return Ok(());
    };
    for dependency in dependencies {
        if dependency.0 != KAIGI_DEPENDENCY_ACTIVE_CALL {
            continue;
        }
        let IndexedKaigiDependency::ActiveCall(record) =
            validate_indexed_kaigi_dependency(&state_transaction.world, relay_id, dependency)
                .map_err(|error| {
                    state_transaction
                        .world
                        .attempt_error_to_instruction_error(error)
                })?
        else {
            return Err(Error::InvariantViolation(
                "Kaigi active-call dependency changed kind during relay preflight".into(),
            ));
        };
        if record
            .relay_manifest
            .as_ref()
            .is_some_and(|manifest| manifest.hops.iter().any(|hop| &hop.relay_id == relay_id))
        {
            return Err(relay_error(format!(
                "cannot {operation} relay {relay_id}: active Kaigi {} manifest still references its registered HPKE key",
                record.id
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        assert_invariant_error, assert_smart_contract_error, load_call_record,
        load_relay_registration, register_manifest_relays, sample_ids, sample_manifest,
        with_state_transaction,
    };
    use super::*;
    use crate::smartcontracts::isi::Execute;
    use iroha_data_model::{
        isi::kaigi::{CreateKaigi, EndKaigi, RegisterKaigiRelay, UnregisterKaigiRelay},
        kaigi::{KaigiId, KaigiRecord, KaigiStatus, NewKaigi},
        prelude::{Account, Domain, Register},
    };
    use iroha_model_base::name::Name;
    use iroha_test_samples::ALICE_ID;
    use std::str::FromStr;

    #[test]
    fn live_manifest_blocks_relay_key_rotation_and_unregister_until_host_end() {
        let (domain, host, _) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("relay-route-retention").expect("call name"),
        );
        let manifest = sample_manifest();
        let relay = manifest.hops[0].relay_id.clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register call and relay home domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            register_manifest_relays(stx, &domain, &manifest);
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create a call with a live registered route");
            stx.world.take_external_events();

            let mut registration =
                load_relay_registration(stx, &domain, &relay).expect("relay has a registered key");
            registration.bandwidth_class = 2;
            RegisterKaigiRelay {
                relay: registration.clone(),
            }
            .execute(&relay, stx)
            .expect("bandwidth-only update does not strand the route");
            stx.world.take_external_events();
            let previous_record: KaigiRecord = load_call_record(stx, &call);
            let internal_events_before = stx.world.internal_event_buf.len();

            let mut rotated = registration.clone();
            rotated.hpke_public_key = vec![0xAA, 0xBB];
            let error = RegisterKaigiRelay {
                relay: rotated.clone(),
            }
            .execute(&relay, stx)
            .expect_err("a live manifest must pin the old HPKE key");
            assert_smart_contract_error(error, "active Kaigi");
            assert_eq!(
                load_relay_registration(stx, &domain, &relay),
                Some(registration.clone())
            );
            assert_eq!(load_call_record(stx, &call), previous_record);
            assert!(stx.world.take_external_events().is_empty());
            assert_eq!(stx.world.internal_event_buf.len(), internal_events_before);

            let error = UnregisterKaigiRelay {
                relay_id: relay.clone(),
            }
            .execute(&relay, stx)
            .expect_err("a live manifest must retain its relay registration");
            assert_smart_contract_error(error, "active Kaigi");
            assert_eq!(
                load_relay_registration(stx, &domain, &relay),
                Some(registration)
            );
            assert_eq!(load_call_record(stx, &call), previous_record);
            assert!(stx.world.take_external_events().is_empty());
            assert_eq!(stx.world.internal_event_buf.len(), internal_events_before);

            EndKaigi {
                call_id: call.clone(),
                ended_at_ms: None,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("the actual host ends the call");
            assert_eq!(load_call_record(stx, &call).status, KaigiStatus::Ended);
            stx.world.take_external_events();
            RegisterKaigiRelay {
                relay: rotated.clone(),
            }
            .execute(&relay, stx)
            .expect("key rotation is available after the retained call ends");
            assert_eq!(load_relay_registration(stx, &domain, &relay), Some(rotated));
            stx.world.take_external_events();
            UnregisterKaigiRelay {
                relay_id: relay.clone(),
            }
            .execute(&relay, stx)
            .expect("retirement is available after the retained call ends");
            assert!(load_relay_registration(stx, &domain, &relay).is_none());
        });
    }

    #[test]
    fn corrupt_active_call_locator_fails_closed_before_relay_update() {
        let (domain, host, _) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("relay-route-locator").expect("call name"),
        );
        let manifest = sample_manifest();
        let relay = manifest.hops[0].relay_id.clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register call and relay home domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            register_manifest_relays(stx, &domain, &manifest);
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create a call with a registered route");
            stx.world.take_external_events();
            let missing_call_key = iroha_data_model::kaigi::kaigi_metadata_key(
                &Name::from_str("a-missing-call").expect("missing call name"),
            )
            .expect("missing call metadata key");
            stx.world
                .kaigi_account_dependencies
                .get_mut(&relay)
                .expect("relay dependency bucket")
                .insert((
                    KAIGI_DEPENDENCY_ACTIVE_CALL,
                    domain.clone(),
                    missing_call_key,
                ));
            let registration =
                load_relay_registration(stx, &domain, &relay).expect("relay registration");
            let mut rotated = registration.clone();
            rotated.hpke_public_key = vec![0xAA, 0xBB];
            let internal_events_before = stx.world.internal_event_buf.len();
            let error = RegisterKaigiRelay { relay: rotated }
                .execute(&relay, stx)
                .expect_err("corrupt indexed call evidence must not authorize key rotation");
            assert_invariant_error(error, "references missing metadata");
            assert_eq!(
                load_relay_registration(stx, &domain, &relay),
                Some(registration)
            );
            assert!(stx.world.take_external_events().is_empty());
            assert_eq!(stx.world.internal_event_buf.len(), internal_events_before);
        });
    }
}
