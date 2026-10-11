//! Exact ledger-context projection for the final Kaigi authorization relation.
//!
//! Core owns the network, permanent call identity, original account identities,
//! participation sequence and current roster root. The circuit proves the
//! private opening and action authorization against that complete projection.

use super::super::{
    persisted_kaigi_rekey_component, persisted_kaigi_rekey_graph,
    resolve_active_kaigi_account_with_graph,
};
use super::{Error, privacy_error};
use crate::state::StateTransaction;
use ff::PrimeField as _;
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    kaigi::{
        KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1, KaigiId, authorization::KaigiAuthorizationIdentitiesV1,
        participation::KaigiPrivateParticipationLedgerV1,
    },
    prelude::AccountId,
};
use kaigi_zk::Scalar as Fp;
use std::collections::BTreeSet;

/// Resolve the immutable participation owner through authenticated rekey state.
pub(crate) fn original_participant_v1(
    state: &StateTransaction<'_, '_>,
    ledger: &KaigiPrivateParticipationLedgerV1,
    host: &AccountId,
    authority: &AccountId,
    participant: &AccountId,
    action: KaigiAuthorizationActionV1,
) -> Result<AccountId, Error> {
    if authority != participant {
        return Err(privacy_error(
            "private Kaigi participation must be signed by the participant",
        ));
    }
    // Expand only this component. Unrelated participant histories do not
    // consume its continuity work limit.
    let graph = persisted_kaigi_rekey_graph(&state.world, [authority.clone()])?;
    if resolve_active_kaigi_account_with_graph(state, authority, &graph)?.as_ref()
        != Some(authority)
    {
        return Err(privacy_error(
            "private Kaigi signer is not its registered active successor",
        ));
    }
    let component = persisted_kaigi_rekey_component(&graph.neighbours, authority);
    original_participant_in_component_v1(ledger, host, authority, &component, action)
}

fn original_participant_in_component_v1(
    ledger: &KaigiPrivateParticipationLedgerV1,
    host: &AccountId,
    authority: &AccountId,
    component: &BTreeSet<AccountId>,
    action: KaigiAuthorizationActionV1,
) -> Result<AccountId, Error> {
    if !matches!(
        action,
        KaigiAuthorizationActionV1::Join | KaigiAuthorizationActionV1::Leave
    ) || !component.contains(authority)
        || component.contains(host)
    {
        return Err(privacy_error(
            "invalid private Kaigi participant lineage or action",
        ));
    }
    // Retain departed subjects too: otherwise rejoining through a successor
    // could reset the original sequence to one.
    let mut matched = ledger
        .entries()
        .iter()
        .filter(|entry| component.contains(entry.original_account()));
    let first = matched.next();
    if matched.next().is_some() {
        return Err(privacy_error(
            "multiple retained Kaigi subjects share one account rekey lineage",
        ));
    }
    match first {
        Some(entry) => Ok(entry.original_account().clone()),
        None if action == KaigiAuthorizationActionV1::Join => Ok(authority.clone()),
        None => Err(privacy_error(
            "private Kaigi participant has no retained participation",
        )),
    }
}

/// Reserve a nullifier for every live member's leave and for host termination.
///
/// The counts come from a validated call record. Admission must not consume
/// space needed to leave or end that same call. A host end releases all future
/// leave reservations because the call becomes permanently terminal.
pub(crate) fn ensure_action_capacity_v1(
    nullifier_count: usize,
    live_participants: usize,
    action: KaigiAuthorizationActionV1,
) -> Result<(), Error> {
    let next_live = match action {
        KaigiAuthorizationActionV1::HostCreate => {
            if nullifier_count != 0 || live_participants != 0 {
                return Err(privacy_error(
                    "Kaigi host creation requires empty action state",
                ));
            }
            Some(0)
        }
        KaigiAuthorizationActionV1::Join => live_participants.checked_add(1),
        KaigiAuthorizationActionV1::Leave => live_participants.checked_sub(1),
        KaigiAuthorizationActionV1::HostEnd => Some(0),
    }
    .ok_or_else(|| privacy_error("invalid Kaigi live participation count"))?;
    let reserved = if action == KaigiAuthorizationActionV1::HostEnd {
        Some(0)
    } else {
        next_live.checked_add(1)
    }
    .ok_or_else(|| privacy_error("Kaigi action reservation overflow"))?;
    if nullifier_count
        .checked_add(1)
        .and_then(|next| next.checked_add(reserved))
        .is_none_or(|required| required > KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1)
    {
        return Err(privacy_error(
            "Kaigi action history must reserve every live leave and host end",
        ));
    }
    Ok(())
}
use kaigi_zk::authorization_v1::{
    KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1, KaigiAuthorizationActionV1, KaigiAuthorizationContextV1,
    KaigiAuthorizationOutputsV1, KaigiAuthorizationPublicInputsV1,
};

/// Project authenticated state into the circuit's complete public context.
///
/// Account lineage and current signer checks must precede this projection.
/// In particular, `subject` is the immutable original participation owner,
/// which can differ from its authenticated active rekey successor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn context_from_ledger_v1(
    network_id: NetworkId,
    call_id: &KaigiId,
    host: &AccountId,
    subject: &AccountId,
    sequence: u64,
    action: KaigiAuthorizationActionV1,
    pre_roster_root: &Hash,
) -> Result<KaigiAuthorizationContextV1, Error> {
    let identities = KaigiAuthorizationIdentitiesV1::new(network_id, call_id, host, subject)
        .map_err(|error| {
            privacy_error(format!("cannot bind canonical Kaigi identities: {error}"))
        })?;
    let context = KaigiAuthorizationContextV1 {
        network_id: *network_id.as_bytes(),
        call_id: identities.call_id.words(),
        host_id: identities.host_id.words(),
        subject_id: identities.subject_id.words(),
        participation_sequence: sequence,
        action,
        pre_roster_root: (*pre_roster_root).into(),
    };
    context
        .validate()
        .map_err(|error| privacy_error(format!("invalid Kaigi authorization context: {error}")))?;
    Ok(context)
}

/// Require one exact 31-row column and all externally authenticated values.
///
/// C and N are canonical raw Pasta scalar representations, never `Hash`
/// values. A is a circuit output: its correctness requires the subsequent
/// canonical proof verification, not an independently chosen instruction field.
pub(crate) fn verify_public_inputs_v1(
    columns: &[Vec<Fp>],
    context: &KaigiAuthorizationContextV1,
    commitment: &[u8; 32],
    nullifier: &[u8; 32],
) -> Result<(), Error> {
    context
        .validate()
        .map_err(|error| privacy_error(format!("invalid Kaigi authorization context: {error}")))?;
    let [column] = columns else {
        return Err(privacy_error(
            "Kaigi authorization requires exactly one instance column",
        ));
    };
    if column.len() != KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1 {
        return Err(privacy_error(
            "Kaigi authorization requires exactly 31 instance rows",
        ));
    }
    let commitment = Option::<Fp>::from(Fp::from_repr(*commitment))
        .ok_or_else(|| privacy_error("Kaigi commitment is not a canonical Pasta scalar"))?;
    let nullifier = Option::<Fp>::from(Fp::from_repr(*nullifier))
        .ok_or_else(|| privacy_error("Kaigi nullifier is not a canonical Pasta scalar"))?;
    let expected = KaigiAuthorizationPublicInputsV1 {
        context: *context,
        outputs: KaigiAuthorizationOutputsV1 {
            commitment,
            nullifier,
            authorization: column[30],
        },
    }
    .instance();
    if column.as_slice() != expected {
        return Err(privacy_error(
            "Kaigi authorization differs from the authenticated ledger context",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use kaigi_zk::authorization_v1::{KaigiAuthorizationWitnessV1, compute_authorization_v1};
    use std::str::FromStr as _;

    #[test]
    fn retained_original_subject_survives_leave_and_successor_rejoin() {
        use KaigiAuthorizationActionV1::{Join, Leave};
        use iroha_data_model::kaigi::scalar::KaigiAuthorizationScalarV1;
        let original = account(1);
        let successor = account(2);
        let host = account(3);
        let foreign = account(4);
        let component = BTreeSet::from([original.clone(), successor.clone()]);
        let mut ledger = KaigiPrivateParticipationLedgerV1::default();
        let commitment = KaigiAuthorizationScalarV1::from_le_bytes([0x24; 32]).unwrap();
        ledger.commit_join(&original, 1, commitment).unwrap();
        for action in [Join, Leave] {
            assert_eq!(
                original_participant_in_component_v1(
                    &ledger, &host, &successor, &component, action
                )
                .unwrap(),
                original
            );
        }
        assert!(ledger.prepare_join(&original).is_err());
        ledger.commit_leave(&original, 1, commitment).unwrap();
        let retained =
            original_participant_in_component_v1(&ledger, &host, &successor, &component, Join)
                .unwrap();
        assert_eq!(retained, original);
        assert_eq!(ledger.prepare_join(&retained).unwrap(), 2);
        let unrelated = BTreeSet::from([foreign.clone()]);
        assert_eq!(
            original_participant_in_component_v1(&ledger, &host, &foreign, &unrelated, Join)
                .unwrap(),
            foreign
        );
        assert!(
            original_participant_in_component_v1(&ledger, &host, &foreign, &unrelated, Leave)
                .is_err()
        );
        assert!(
            original_participant_in_component_v1(&ledger, &original, &successor, &component, Join)
                .is_err()
        );
        assert!(
            original_participant_in_component_v1(&ledger, &host, &foreign, &component, Join)
                .is_err()
        );
        ledger
            .commit_join(&successor, 1, KaigiAuthorizationScalarV1::default())
            .unwrap();
        assert!(
            original_participant_in_component_v1(&ledger, &host, &successor, &component, Join)
                .is_err()
        );
    }

    #[test]
    fn action_budget_reserves_leave_and_end_before_accepting_another_join() {
        use KaigiAuthorizationActionV1::{HostCreate, HostEnd, Join, Leave};
        let cap = KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1;
        assert!(ensure_action_capacity_v1(0, 0, HostCreate).is_ok());
        assert!(ensure_action_capacity_v1(1, 0, HostCreate).is_err());
        assert!(ensure_action_capacity_v1(0, 1, HostCreate).is_err());
        assert!(ensure_action_capacity_v1(cap - 3, 0, Join).is_ok());
        assert!(ensure_action_capacity_v1(cap - 2, 1, Leave).is_ok());
        assert!(ensure_action_capacity_v1(cap - 1, 0, Join).is_err());
        assert!(ensure_action_capacity_v1(cap - 1, 0, HostEnd).is_ok());
        assert!(ensure_action_capacity_v1(cap, 0, HostEnd).is_err());
        assert!(ensure_action_capacity_v1(1, 0, Leave).is_err());
        assert!(ensure_action_capacity_v1(usize::MAX, 0, HostEnd).is_err());
        assert!(ensure_action_capacity_v1(1, usize::MAX, Join).is_err());
        // Every outstanding leave fits even when the reservation is exact.
        for live in 1..=16 {
            assert!(ensure_action_capacity_v1(cap - live - 1, live, Leave).is_ok());
            assert!(ensure_action_capacity_v1(cap - live - 1, live, Join).is_err());
        }
    }

    fn account(seed: u8) -> AccountId {
        AccountId::new(
            KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    }
    fn context(action: KaigiAuthorizationActionV1) -> KaigiAuthorizationContextV1 {
        let host = account(1);
        let subject = if matches!(
            action,
            KaigiAuthorizationActionV1::HostCreate | KaigiAuthorizationActionV1::HostEnd
        ) {
            host.clone()
        } else {
            account(2)
        };
        context_from_ledger_v1(
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new([3; 32]))),
            &KaigiId::new(
                DomainId::try_new("wonderland", "universal").unwrap(),
                Name::from_str("meeting").unwrap(),
            ),
            &host,
            &subject,
            u64::from(subject != host),
            action,
            &Hash::new(b"authenticated pre-state root"),
        )
        .unwrap()
    }

    #[test]
    fn ledger_projection_preserves_complete_context_and_enforces_roles() {
        for action in [
            KaigiAuthorizationActionV1::HostCreate,
            KaigiAuthorizationActionV1::Join,
            KaigiAuthorizationActionV1::Leave,
            KaigiAuthorizationActionV1::HostEnd,
        ] {
            let context = context(action);
            assert_eq!(context.action, action);
            assert_eq!(
                context.pre_roster_root,
                <[u8; 32]>::from(Hash::new(b"authenticated pre-state root"))
            );
            assert_eq!(
                context.host_id == context.subject_id,
                context.participation_sequence == 0
            );
            assert!(context.validate().is_ok());
        }
        let mut invalid = context(KaigiAuthorizationActionV1::Join);
        invalid.subject_id = invalid.host_id;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn public_projection_rejects_every_external_row_and_noncanonical_scalar() {
        let context = context(KaigiAuthorizationActionV1::Join);
        let mut secret = [0_u8; 32];
        secret[0] = 9;
        let witness = KaigiAuthorizationWitnessV1::take_blinding(&mut secret).unwrap();
        let outputs = compute_authorization_v1(&context, &witness).unwrap();
        let [commitment, nullifier, _] = outputs.canonical_bytes();
        let column = KaigiAuthorizationPublicInputsV1 { context, outputs }
            .instance()
            .to_vec();
        verify_public_inputs_v1(&[column.clone()], &context, &commitment, &nullifier).unwrap();
        for row in 0..30 {
            let mut changed = column.clone();
            changed[row] += Fp::from(1);
            assert!(
                verify_public_inputs_v1(&[changed], &context, &commitment, &nullifier).is_err(),
                "row {row}"
            );
        }
        for malformed in [
            Vec::new(),
            vec![column.clone(), column.clone()],
            vec![column[..30].to_vec()],
            vec![[column.clone(), vec![Fp::from(1)]].concat()],
        ] {
            assert!(
                verify_public_inputs_v1(&malformed, &context, &commitment, &nullifier).is_err()
            );
        }
        assert!(
            verify_public_inputs_v1(&[column.clone()], &context, &[255; 32], &nullifier).is_err()
        );
        assert!(verify_public_inputs_v1(&[column], &context, &commitment, &[255; 32]).is_err());
    }
}
