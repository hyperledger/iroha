//! Exact wallet-authorized equipment admission and terminal-only returns.
use super::*;
use crate::smartcontracts::isi::nft_custody::{
    PreparedNftReservationsV1, nft_custody_account_v1, prepare_nft_reservations_v1,
};
use crate::state::World;
use iroha_data_model::nft_market::NftCustodyPurposeV1;

pub(super) struct PreparedGameResources {
    native: PreparedNftReservationsV1,
    records: Vec<GameResourceReservationRecordV1>,
}
pub(super) fn prepare_admission(
    st: &StateTransaction<'_, '_>,
    session: &GameSessionRecordV1,
    participant: &GameParticipantV1,
    clauses: &[GameResourceReservationClauseV1],
) -> Result<PreparedGameResources, Error> {
    let requirements = crate::execution_proofs::game_resource_requirements_v1(
        &session.manifest,
        &participant.application_data,
    )
    .map_err(|e| invalid(format!("compiled resource requirements rejected: {e}")))?;
    match_resource_requirements_v1(clauses, &requirements).map_err(invalid)?;
    let native = prepare_nft_reservations_v1(
        st,
        &participant.account,
        session.session_id,
        NftCustodyPurposeV1::GameResource,
        clauses
            .iter()
            .map(|clause| (clause.nft_id.clone(), clause.expected_metadata_hash))
            .collect(),
    )?;
    let slot = u8::try_from(session.participants.len())
        .map_err(|_| invalid("resource owner slot exceeds bound"))?;
    let records = native
        .records()
        .zip(clauses)
        .map(|(record, clause)| GameResourceReservationRecordV1 {
            slot,
            nft_id: record.nft_id.clone(),
            metadata_hash: record.metadata_hash,
            role_id: clause.role_id,
            policy: clause.policy,
            original_owner: participant.account.clone(),
            custody: record.custody.clone(),
            reserved_at_height: st.block_height(),
            released_at_height: None,
        })
        .collect::<Vec<_>>();
    let mut projected = session.clone();
    projected.participants.push(participant.clone());
    projected.resources.extend(records.iter().cloned());
    GameAdmissionBodyV1::from_session(&projected)
        .validate()
        .map_err(invalid)?;
    validate_record_geometry(&projected).map_err(invalid)?;
    // Returning every resource adds terminal option payloads. Reserve their worst
    // canonical encoding now so a legal terminal transition cannot exceed the set cap.
    for resource in &mut projected.resources {
        resource.released_at_height = Some(u64::MAX);
    }
    validate_record_geometry(&projected).map_err(invalid)?;
    Ok(PreparedGameResources { native, records })
}
pub(super) fn apply_admission(
    st: &mut StateTransaction<'_, '_>,
    session: &mut GameSessionRecordV1,
    prepared: PreparedGameResources,
) {
    prepared.native.apply(st);
    session.resources.extend(prepared.records);
}
pub(super) fn same_reserved_resources(
    before: &[GameResourceReservationRecordV1],
    after: &[GameResourceReservationRecordV1],
) -> bool {
    before.len() == after.len()
        && before.iter().zip(after).all(|(a, b)| {
            a.slot == b.slot
                && a.nft_id == b.nft_id
                && a.metadata_hash == b.metadata_hash
                && a.role_id == b.role_id
                && a.policy == b.policy
                && a.original_owner == b.original_owner
                && a.custody == b.custody
                && a.reserved_at_height == b.reserved_at_height
        })
}
fn validate_record_geometry(session: &GameSessionRecordV1) -> Result<(), String> {
    GameResourceReservationSetV1 {
        version: 1,
        network_id: session.network_id,
        session_id: session.session_id,
        records: session.resources.clone(),
    }
    .validate_for_owners(
        &session
            .participants
            .iter()
            .map(|p| p.account.clone())
            .collect::<Vec<_>>(),
    )
    .map_err(str::to_owned)
}
/// Cross-check the complete retained authorization, phase and exact native custody record.
pub(crate) fn validate_restored_resources(
    world: &World,
    session: &GameSessionRecordV1,
) -> Result<(), String> {
    crate::execution_proofs::validate_game_manifest_v1(&session.manifest)
        .map_err(|error| format!("restored game manifest rejected: {error}"))?;
    validate_record_geometry(session)?;
    GameAdmissionBodyV1::from_session(session).validate()?;
    let closed = matches!(session.phase, GamePhaseV1::Settled | GamePhaseV1::Cancelled);
    if closed != session.terminal_at_height.is_some() || session.terminal_at_height == Some(0) {
        return Err("game terminal phase and height differ".into());
    }
    if session.phase != GamePhaseV1::Lobby
        && session.roster_hash
            != game_roster_hash_v1(
                &session.network_id,
                &session.session_id,
                &GameAdmissionBodyV1::from_session(session),
            )
    {
        return Err("game resource admission differs from its immutable commitment".into());
    }
    for (slot, participant) in session.participants.iter().enumerate() {
        let requirements = crate::execution_proofs::game_resource_requirements_v1(
            &session.manifest,
            &participant.application_data,
        )
        .map_err(|error| format!("restored game resource requirements rejected: {error}"))?;
        let clauses = session
            .resources
            .iter()
            .filter(|r| usize::from(r.slot) == slot)
            .map(|r| GameResourceReservationClauseV1 {
                nft_id: r.nft_id.clone(),
                expected_metadata_hash: r.metadata_hash,
                role_id: r.role_id,
                policy: r.policy,
            })
            .collect::<Vec<_>>();
        match_resource_requirements_v1(&clauses, &requirements).map_err(str::to_owned)?;
    }
    let records = world.nft_custody_records.view();
    for resource in &session.resources {
        let owner = session
            .participants
            .get(usize::from(resource.slot))
            .ok_or("resource owner slot absent")?;
        let record = records
            .get(&resource.custody)
            .ok_or("resource custody record absent")?;
        let recipient = closed.then_some(&resource.original_owner);
        if resource.original_owner != owner.account
            || resource.custody
                != nft_custody_account_v1(
                    &session.network_id,
                    &session.session_id,
                    NftCustodyPurposeV1::GameResource,
                    &resource.nft_id,
                )
            || resource.released_at_height != session.terminal_at_height
            || resource.reserved_at_height == 0
            || session
                .terminal_at_height
                .is_some_and(|height| height < resource.reserved_at_height)
            || record.purpose != NftCustodyPurposeV1::GameResource
            || record.version != 1
            || record.network_id != session.network_id
            || record.reservation_id != session.session_id
            || record.nft_id != resource.nft_id
            || record.custody != resource.custody
            || record.original_owner != resource.original_owner
            || record.metadata_hash != resource.metadata_hash
            || record.released_to.as_ref() != recipient
        {
            return Err("retained equipment differs from original-owner terminal custody".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fund_payout_fixture, header, key, payout_state, payout_transaction};
    use super::*;
    use crate::smartcontracts::isi::nft_custody::reserve_nft_v1;
    use iroha_data_model::{
        isi::Register,
        nft::{Nft, NftId},
    };
    use iroha_model_base::metadata::Metadata;

    fn register(st: &mut StateTransaction<'_, '_>, owner: &AccountId, name: &str) -> (NftId, Hash) {
        let nft_id: NftId = format!("{name}$session.universal").parse().unwrap();
        Register::nft(Nft::new(nft_id.clone(), Metadata::default()))
            .execute(owner, st)
            .unwrap();
        let hash = Hash::new(st.world.nft(&nft_id).unwrap().value().content.encode());
        (nft_id, hash)
    }
    #[test]
    fn reservation_preflight_is_atomic_for_wrong_metadata_and_cumulative_overflow() {
        let (state, mut session, _) = payout_state(Quantity::zero());
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        let owner = session.participants[0].account.clone();
        let first = register(&mut st, &owner, "equipment_a");
        let second = register(&mut st, &owner, "equipment_b");
        let wrong = vec![
            first.clone(),
            (second.0.clone(), Hash::new(b"altered metadata")),
        ];
        assert!(
            prepare_nft_reservations_v1(
                &st,
                &owner,
                session.session_id,
                NftCustodyPurposeV1::GameResource,
                wrong
            )
            .is_err()
        );
        assert!(st.world.nft_custody_records.iter().next().is_none());
        assert_eq!(st.world.nft(&first.0).unwrap().value().owned_by, owner);
        st.world
            .nft_custody_owner_refs
            .insert(owner.clone(), u32::MAX - 1);
        assert!(
            prepare_nft_reservations_v1(
                &st,
                &owner,
                session.session_id,
                NftCustodyPurposeV1::GameResource,
                vec![first, second]
            )
            .is_err()
        );
        assert_eq!(
            st.world.nft_custody_owner_refs.get(&owner),
            Some(&(u32::MAX - 1))
        );
        assert!(st.world.nft_custody_records.iter().next().is_none());
    }
    #[test]
    fn zero_xor_entry_never_reserves_unqualified_equipment_and_stock_requires_empty_clauses() {
        let (state, mut session, outsider) = payout_state(Quantity::zero());
        session.phase = GamePhaseV1::Lobby;
        session.stake = Quantity::zero();
        session.liability = Quantity::zero();
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        let clause = GameResourceReservationClauseV1 {
            nft_id: "unreserved$session.universal".parse().unwrap(),
            expected_metadata_hash: Hash::new(b"metadata"),
            role_id: Hash::new(b"engine"),
            policy: GameResourceReturnPolicyV1::ReturnToOriginalOwnerAtTerminal,
        };
        let participant = GameParticipantV1 {
            account: outsider.clone(),
            input_key: key(29).public_key().clone(),
            application_data: vec![0],
            dnf_at_tick: None,
        };
        assert!(
            prepare_admission(&st, &session, &participant, std::slice::from_ref(&clause)).is_err()
        );
        let error = JoinGameSessionV1 {
            session_id: session.session_id,
            input_key: participant.input_key,
            application_data: vec![0],
            resources: vec![clause],
            invitation: None,
            expected_manifest_hash: session.manifest_hash,
            expected_asset_definition: session.asset_definition.clone(),
            expected_stake: Quantity::zero(),
        }
        .execute(&outsider, &mut st)
        .unwrap_err();
        assert!(error.to_string().contains("qualification"), "{error}");
        assert_eq!(get(&st, &session.session_id).unwrap(), session);
        assert!(st.world.nft_custody_records.iter().next().is_none());
    }
    #[test]
    fn wagers_and_equipment_release_with_one_cumulative_counter_set_and_original_equipment_owner() {
        let (state, mut session, _) = payout_state(Quantity::zero());
        session.phase = GamePhaseV1::Lobby;
        session.stake = Quantity::zero();
        session.liability = Quantity::zero();
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        // Directly exercise native custody primitives; no profile is qualified or public admission bypassed.
        for slot in 0..2 {
            let owner = session.participants[slot].account.clone();
            let (nft_id, _) = register(&mut st, &owner, &format!("wager_{slot}"));
            let record = reserve_nft_v1(
                &mut st,
                &owner,
                session.session_id,
                NftCustodyPurposeV1::GameWager,
                &nft_id,
            )
            .unwrap();
            session.item_stakes.push(GameItemStakeV1 {
                slot: u8::try_from(slot).expect("fixture value fits u8"),
                nft_id,
                custody: record.custody,
                metadata_hash: record.metadata_hash,
                recipient: None,
                claimed: false,
            });
        }
        let original = session.participants[0].account.clone();
        for role in 0..2_u8 {
            let (nft_id, _) = register(&mut st, &original, &format!("equipment_{role}"));
            let record = reserve_nft_v1(
                &mut st,
                &original,
                session.session_id,
                NftCustodyPurposeV1::GameResource,
                &nft_id,
            )
            .unwrap();
            session.resources.push(GameResourceReservationRecordV1 {
                slot: 0,
                nft_id,
                metadata_hash: record.metadata_hash,
                role_id: Hash::prehashed([role; 32]),
                policy: GameResourceReturnPolicyV1::ReturnToOriginalOwnerAtTerminal,
                original_owner: original.clone(),
                custody: record.custody,
                reserved_at_height: st.block_height(),
                released_at_height: None,
            });
        }
        assert_eq!(st.world.nft_custody_owner_refs.get(&original), Some(&3));
        let mut restored = World::default();
        restored.nft_custody_records = st
            .world
            .nft_custody_records
            .iter()
            .map(|(id, record)| (id.clone(), record.clone()))
            .collect();
        session.roster_hash = game_roster_hash_v1(
            &session.network_id,
            &session.session_id,
            &GameAdmissionBodyV1::from_session(&session),
        );
        let error = validate_restored_resources(&restored, &session).unwrap_err();
        assert!(error.contains("compiled requirements"), "{error}");
        session.phase = GamePhaseV1::Playing;
        session.deadline_height = 0;
        save(&mut st, session.clone()).unwrap();
        assert!(
            ExpireGameSessionV1::new(session.session_id)
                .execute(&original, &mut st)
                .is_err()
        );
        assert_eq!(st.world.nft_custody_owner_refs.get(&original), Some(&3));
        let prepared = items::prepare_item_payouts(&st, &session, &[1]).unwrap();
        items::apply_item_payouts(&mut st, &mut session, prepared);
        for wager in &session.item_stakes {
            assert_eq!(
                st.world.nft(&wager.nft_id).unwrap().value().owned_by,
                session.participants[1].account
            );
        }
        for resource in &session.resources {
            assert_eq!(
                st.world.nft(&resource.nft_id).unwrap().value().owned_by,
                original
            );
            assert_eq!(resource.released_at_height, Some(st.block_height()));
        }
        assert!(st.world.nft_custody_by_nft.iter().next().is_none());
        assert!(st.world.nft_custody_owner_refs.iter().next().is_none());
        assert!(st.world.nft_custody_domain_refs.iter().next().is_none());
        assert!(items::prepare_item_payouts(&st, &session, &[1]).is_err());
    }
}
