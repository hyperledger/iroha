//! Explicit generic game NFT stakes. The simulation relation never selects item recipients.
use super::*;
use crate::smartcontracts::isi::nft_custody::{
    PreparedNftReleasesV1, PreparedNftReservationsV1, prepare_nft_releases_v1,
    prepare_nft_reservations_v1,
};
use crate::state::World;
use iroha_data_model::nft_market::NftCustodyPurposeV1;
use std::collections::BTreeSet;

impl Execute for StakeGameItemV1 {
    fn execute(
        self,
        authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let mut session = get(st, &self.session_id)?;
        let slot = validate_item_admission(
            &session,
            authority,
            &self.expected_manifest_hash,
            st.block_height(),
        )?;
        // A free lobby may predate its first item deposit. A participant could
        // legally have removed/rekeyed its account before any value was reserved.
        // Never accept an item while a possible winner's wallet is already absent.
        for participant in &session.participants {
            st.world
                .account(&participant.account)
                .map_err(|_| invalid("a previously joined game wallet no longer exists"))?;
        }
        let profile = crate::execution_proofs::compiled_execution_profile_v1(&session.profile_id)
            .ok_or_else(|| invalid("game item proof profile is not compiled"))?;
        if !profile.qualified {
            return Err(invalid(
                "execution proof profile has not passed qualification; item funding disabled",
            ));
        }
        let (native, item) = prepare_item_reservation(st, &session, authority, slot, &self.nft_id)?;
        native.apply(st);
        session.item_stakes.push(item);
        session.item_stakes.sort_by_key(|item| item.slot);
        save(st, session)
    }
}
fn prepare_item_reservation(
    st: &StateTransaction<'_, '_>,
    session: &GameSessionRecordV1,
    authority: &AccountId,
    slot: u8,
    nft_id: &iroha_data_model::nft::NftId,
) -> Result<(PreparedNftReservationsV1, GameItemStakeV1), Error> {
    if session
        .participants
        .get(usize::from(slot))
        .map(|p| &p.account)
        != Some(authority)
    {
        return Err(invalid(
            "wager reservation owner differs from its permanent slot",
        ));
    }
    let metadata_hash = Hash::new(st.world.nft(nft_id)?.value().content.encode());
    let native = prepare_nft_reservations_v1(
        st,
        authority,
        session.session_id,
        NftCustodyPurposeV1::GameWager,
        vec![(nft_id.clone(), metadata_hash)],
    )?;
    let record = native
        .records()
        .next()
        .ok_or_else(|| invalid("wager reservation preflight is empty"))?;
    let item = GameItemStakeV1 {
        slot,
        nft_id: nft_id.clone(),
        custody: record.custody.clone(),
        metadata_hash: record.metadata_hash,
        recipient: None,
        claimed: false,
    };
    let mut projected = session.clone();
    projected.item_stakes.push(item.clone());
    projected.item_stakes.sort_by_key(|item| item.slot);
    GameAdmissionBodyV1::from_session(&projected)
        .validate()
        .map_err(invalid)?;
    Ok((native, item))
}
fn validate_item_admission(
    session: &GameSessionRecordV1,
    authority: &AccountId,
    manifest_hash: &Hash,
    height: u64,
) -> Result<u8, Error> {
    let slot = session
        .participants
        .iter()
        .position(|participant| &participant.account == authority)
        .ok_or_else(|| invalid("only an already-joined wallet may stake a game item"))?;
    if session.phase != GamePhaseV1::Lobby
        || height > session.deadline_height
        || manifest_hash != &session.manifest_hash
        || session.item_stakes.len() >= GAME_MAX_PARTICIPANTS_V1
        || session
            .item_stakes
            .iter()
            .any(|item| usize::from(item.slot) == slot)
    {
        return Err(invalid(
            "game item stake requires its approved lobby manifest and one unfilled item slot",
        ));
    }
    u8::try_from(slot).map_err(|_| invalid("game item participant slot exceeds its wire bound"))
}
pub(super) fn same_staked_items(before: &[GameItemStakeV1], after: &[GameItemStakeV1]) -> bool {
    before.len() == after.len()
        && before.iter().zip(after).all(|(a, b)| {
            a.slot == b.slot
                && a.nft_id == b.nft_id
                && a.custody == b.custody
                && a.metadata_hash == b.metadata_hash
        })
}
fn item_recipient(
    session: &GameSessionRecordV1,
    item: &GameItemStakeV1,
    winners: &[u8],
) -> Result<AccountId, Error> {
    let slot = if winners.len() == 1 {
        winners[0]
    } else {
        item.slot
    };
    session
        .participants
        .get(usize::from(slot))
        .map(|participant| participant.account.clone())
        .ok_or_else(|| invalid("native game item award references an absent slot"))
}
pub(super) struct PreparedGameItems {
    native: PreparedNftReleasesV1,
    recipients: Vec<AccountId>,
}
pub(super) fn prepare_item_payouts(
    st: &StateTransaction<'_, '_>,
    session: &GameSessionRecordV1,
    winners: &[u8],
) -> Result<PreparedGameItems, Error> {
    if session.item_stakes.len() > GAME_MAX_PARTICIPANTS_V1
        || session
            .item_stakes
            .iter()
            .any(|item| item.claimed || item.recipient.is_some())
    {
        return Err(invalid(
            "game item payouts are already consumed or exceed their bound",
        ));
    }
    let recipients = session
        .item_stakes
        .iter()
        .map(|item| item_recipient(session, item, winners))
        .collect::<Result<Vec<_>, _>>()?;
    let mut releases = session
        .item_stakes
        .iter()
        .zip(&recipients)
        .map(|(item, recipient)| {
            (
                session.session_id,
                NftCustodyPurposeV1::GameWager,
                item.nft_id.clone(),
                recipient.clone(),
            )
        })
        .collect::<Vec<_>>();
    GameAdmissionBodyV1::from_session(session)
        .validate()
        .map_err(invalid)?;
    if session
        .resources
        .iter()
        .any(|resource| resource.released_at_height.is_some())
    {
        return Err(invalid("game equipment was already returned"));
    }
    for resource in &session.resources {
        let owner = session
            .participants
            .get(usize::from(resource.slot))
            .ok_or_else(|| invalid("game equipment owner slot is absent"))?;
        if owner.account != resource.original_owner {
            return Err(invalid(
                "game equipment original owner differs from its participant",
            ));
        }
        releases.push((
            session.session_id,
            NftCustodyPurposeV1::GameResource,
            resource.nft_id.clone(),
            resource.original_owner.clone(),
        ));
    }
    // Wagers and equipment share one cumulative owner/domain reference preflight.
    Ok(PreparedGameItems {
        native: prepare_nft_releases_v1(st, releases)?,
        recipients,
    })
}
pub(super) fn apply_item_payouts(
    st: &mut StateTransaction<'_, '_>,
    session: &mut GameSessionRecordV1,
    prepared: PreparedGameItems,
) {
    prepared.native.apply(st);
    for resource in &mut session.resources {
        resource.released_at_height = Some(st.block_height());
    }
    for (item, recipient) in session.item_stakes.iter_mut().zip(prepared.recipients) {
        item.recipient = Some(recipient);
        item.claimed = true;
    }
}
/// Cross-check retained item stakes against the exact shared native custody records.
pub(crate) fn validate_restored_items(
    world: &World,
    session: &GameSessionRecordV1,
) -> Result<(), String> {
    let closed = matches!(session.phase, GamePhaseV1::Settled | GamePhaseV1::Cancelled);
    if session.item_stakes.len() > session.participants.len()
        || session
            .item_stakes
            .windows(2)
            .any(|pair| pair[0].slot >= pair[1].slot)
    {
        return Err("game item stakes are not uniquely ordered by permanent slot".into());
    }
    GameAdmissionBodyV1::from_session(session).validate()?;
    if session.phase != GamePhaseV1::Lobby
        && session.roster_hash
            != game_roster_hash_v1(
                &session.network_id,
                &session.session_id,
                &GameAdmissionBodyV1::from_session(session),
            )
    {
        return Err("game starting roster does not commit its exact admission".into());
    }
    let records = world.nft_custody_records.view();
    let mut seen = BTreeSet::new();
    for item in &session.item_stakes {
        let owner = session
            .participants
            .get(usize::from(item.slot))
            .ok_or("game item owner slot is absent")?;
        let record = records
            .get(&item.custody)
            .ok_or("game item custody is absent")?;
        let recipient = if closed {
            let winners = if session.phase == GamePhaseV1::Settled {
                session
                    .result
                    .as_ref()
                    .ok_or("settled item game has no outcome")?
                    .winner_slots
                    .as_slice()
            } else {
                &[]
            };
            Some(item_recipient(session, item, winners).map_err(|error| error.to_string())?)
        } else {
            None
        };
        if !seen.insert(item.nft_id.clone())
            || record.purpose != NftCustodyPurposeV1::GameWager
            || (&record.network_id, &record.reservation_id)
                != (&session.network_id, &session.session_id)
            || record.nft_id != item.nft_id
            || record.original_owner != owner.account
            || record.metadata_hash != item.metadata_hash
            || record.released_to != recipient
            || item.recipient != recipient
            || item.claimed != closed
        {
            return Err(
                "game item stake differs from its immutable custody or native recipient".into(),
            );
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
        Registrable,
        isi::Register,
        nft::{Nft, NftId},
    };
    use iroha_model_base::metadata::Metadata;

    fn reserve_fixture_item(
        st: &mut StateTransaction<'_, '_>,
        session: &mut GameSessionRecordV1,
        slot: u8,
    ) {
        let owner = session.participants[usize::from(slot)].account.clone();
        let nft_id: NftId = format!("skin{slot}$session.universal").parse().unwrap();
        Register::nft(Nft::new(nft_id.clone(), Metadata::default()))
            .execute(&owner, st)
            .unwrap();
        validate_item_admission(session, &owner, &session.manifest_hash, st.block_height())
            .unwrap();
        // Test the custody primitive directly; never qualify or bypass the public funding gate.
        let record = reserve_nft_v1(
            st,
            &owner,
            session.session_id,
            NftCustodyPurposeV1::GameWager,
            &nft_id,
        )
        .unwrap();
        session.item_stakes.push(GameItemStakeV1 {
            slot,
            nft_id,
            custody: record.custody,
            metadata_hash: record.metadata_hash,
            recipient: None,
            claimed: false,
        });
        session.item_stakes.sort_by_key(|item| item.slot);
        save(st, session.clone()).unwrap();
        *session = get(st, &session.session_id).unwrap();
    }
    #[test]
    fn maximum_canonical_native_nft_fits_a_settleable_admission() {
        use iroha_data_model::domain::Domain;
        use iroha_model_base::domain::DomainId;
        let (state, mut session, _) = payout_state(Quantity::zero());
        session.phase = GamePhaseV1::Lobby;
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        let owner = session.participants[0].account.clone();
        let domain_id = DomainId::try_new(&"a".repeat(63), &"b".repeat(63)).unwrap();
        let domain = Domain::new(domain_id.clone()).build(&owner);
        st.world.domains.insert(domain_id.clone(), domain);
        let nft_id = NftId::new(domain_id, "n".repeat(255).parse().unwrap());
        assert!(nft_id.to_string().len() <= GAME_RESOURCE_MAX_NFT_ID_BYTES_V1);
        Register::nft(Nft::new(nft_id.clone(), Metadata::default()))
            .execute(&owner, &mut st)
            .unwrap();
        assert!(prepare_item_reservation(&st, &session, &owner, 0, &nft_id).is_ok());
        assert_eq!(st.world.nft(&nft_id).unwrap().value().owned_by, owner);
        assert!(st.world.nft_custody_records.iter().next().is_none());
        assert!(st.world.nft_custody_owner_refs.iter().next().is_none());
        assert!(st.world.nft_custody_domain_refs.iter().next().is_none());
        assert_eq!(get(&st, &session.session_id).unwrap(), session);
    }
    #[test]
    fn multi_label_domains_cannot_create_ambiguous_native_nft_ids() {
        use iroha_model_base::domain::DomainId;
        let (state, mut session, _) = payout_state(Quantity::zero());
        session.phase = GamePhaseV1::Lobby;
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        for (label, dataspace) in [("art.gallery", "universal"), ("art", "gallery.universal")] {
            assert!(DomainId::try_new(label, dataspace).is_err());
            assert!(st.world.nft_custody_records.iter().next().is_none());
            assert!(st.world.nft_custody_owner_refs.iter().next().is_none());
            assert!(st.world.nft_custody_domain_refs.iter().next().is_none());
            assert_eq!(get(&st, &session.session_id).unwrap(), session);
        }
    }
    #[test]
    fn item_funding_requires_the_joined_wallet_manifest_lobby_and_qualified_profile() {
        let (state, mut session, outsider) = payout_state(Quantity::zero());
        session.stake = Quantity::zero();
        session.liability = Quantity::zero();
        session.phase = GamePhaseV1::Lobby;
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        let owner = session.participants[0].account.clone();
        assert!(validate_item_admission(&session, &outsider, &session.manifest_hash, 1).is_err());
        assert!(validate_item_admission(&session, &owner, &Hash::new(b"other rules"), 1).is_err());
        assert!(
            validate_item_admission(
                &session,
                &owner,
                &session.manifest_hash,
                session.deadline_height + 1
            )
            .is_err()
        );
        for phase in [
            GamePhaseV1::Playing,
            GamePhaseV1::AwaitingProof,
            GamePhaseV1::Cancelled,
            GamePhaseV1::Settled,
        ] {
            let mut altered = session.clone();
            altered.phase = phase;
            assert!(validate_item_admission(&altered, &owner, &session.manifest_hash, 1).is_err());
        }
        let instruction = StakeGameItemV1::new(
            session.session_id,
            "skin$session.universal".parse().unwrap(),
            session.manifest_hash,
        );
        let before = get(&st, &session.session_id).unwrap();
        let error = instruction.execute(&owner, &mut st).unwrap_err();
        assert!(error.to_string().contains("qualification"), "{error}");
        assert_eq!(get(&st, &session.session_id).unwrap(), before);
        assert!(st.world.nft_custody_records.iter().next().is_none());
        let removed_id = session.participants[1].account.clone();
        let removed = st.world.accounts.remove(removed_id.clone()).unwrap();
        let error = StakeGameItemV1::new(
            session.session_id,
            "skin$session.universal".parse().unwrap(),
            session.manifest_hash,
        )
        .execute(&owner, &mut st)
        .unwrap_err();
        assert!(error.to_string().contains("no longer exists"), "{error}");
        assert!(st.world.nft_custody_records.iter().next().is_none());
        st.world.accounts.insert(removed_id, removed);
        reserve_fixture_item(&mut st, &mut session, 0);
        assert!(validate_item_admission(&session, &owner, &session.manifest_hash, 1).is_err());
    }
    #[test]
    fn compact_admission_binds_immutable_terms_and_excludes_derived_and_terminal_state() {
        let (_, mut session, _) = payout_state(Quantity::zero());
        let empty = game_roster_hash_v1(
            &session.network_id,
            &session.session_id,
            &GameAdmissionBodyV1::from_session(&session),
        );
        assert_ne!(
            empty,
            game_message_hash_v1(
                &session.network_id,
                "roster",
                &(session.session_id, session.participants.clone())
            )
        );
        session.item_stakes.push(GameItemStakeV1 {
            slot: 0,
            nft_id: "skin$session.universal".parse().unwrap(),
            custody: AccountId::new(key(30).public_key().clone()),
            metadata_hash: Hash::new(b"original skin"),
            recipient: None,
            claimed: false,
        });
        let body = GameAdmissionBodyV1::from_session(&session);
        let hash = game_roster_hash_v1(&session.network_id, &session.session_id, &body);
        assert_ne!(hash, empty);
        for mutation in 0..3 {
            let mut changed = body.clone();
            match mutation {
                0 => changed.wagers[0].slot = 1,
                1 => changed.wagers[0].nft_id = "different$session.universal".parse().unwrap(),
                _ => changed.wagers[0].metadata_hash = Hash::new(b"forged skin"),
            }
            assert_ne!(
                game_roster_hash_v1(&session.network_id, &session.session_id, &changed),
                hash
            );
        }
        session.participants[0].dnf_at_tick = Some(6);
        session.item_stakes[0].claimed = true;
        session.item_stakes[0].recipient = Some(session.participants[1].account.clone());
        session.item_stakes[0].custody = session.participants[0].account.clone();
        // Custody is recomputed and cross-checked by native restoration, never an authorized free variable.
        assert_eq!(GameAdmissionBodyV1::from_session(&session), body);
    }
    #[test]
    fn sole_winner_receives_exact_items_ties_return_owners_and_all_reserves_release_atomically() {
        for winners in [vec![2], vec![0, 2], vec![]] {
            let (state, mut session, _) = payout_state(Quantity::zero());
            session.stake = Quantity::zero();
            session.liability = Quantity::zero();
            session.phase = GamePhaseV1::Lobby;
            let mut block = state.block(header());
            let mut st = payout_transaction(&mut block);
            fund_payout_fixture(&mut st, &mut session);
            reserve_fixture_item(&mut st, &mut session, 0);
            reserve_fixture_item(&mut st, &mut session, 1);
            assert!(
                session
                    .participants
                    .iter()
                    .all(|participant| retained_game_account(&st.world, &participant.account)),
                "even a non-staking possible winner must remain present"
            );
            StartGameSessionV1::new(session.session_id)
                .execute(&session.participants[0].account, &mut st)
                .unwrap();
            session = get(&st, &session.session_id).unwrap();
            let prepared = prepare_item_payouts(&st, &session, &winners).unwrap();
            apply_item_payouts(&mut st, &mut session, prepared);
            session.phase = GamePhaseV1::Settled;
            session.terminal_at_height = Some(1);
            session.result = Some(GameOutcomeV1 {
                terminal_tick: 5400,
                winner_slots: winners.clone(),
                result: vec![],
            });
            save(&mut st, session.clone()).unwrap();
            for item in &session.item_stakes {
                let expected = item_recipient(&session, item, &winners).unwrap();
                assert_eq!(
                    st.world.nft(&item.nft_id).unwrap().value().owned_by,
                    expected
                );
                assert_eq!(item.recipient, Some(expected));
                assert!(item.claimed);
            }
            assert!(st.world.nft_custody_by_nft.iter().next().is_none());
            assert!(st.world.nft_custody_owner_refs.iter().next().is_none());
            assert!(st.world.nft_custody_domain_refs.iter().next().is_none());
            assert!(st.world.game_account_references.iter().next().is_none());
            assert!(prepare_item_payouts(&st, &session, &winners).is_err());
            let mut restored = World::default();
            restored.nft_custody_records = st
                .world
                .nft_custody_records
                .iter()
                .map(|(id, record)| (id.clone(), record.clone()))
                .collect();
            validate_restored_items(&restored, &session).unwrap();
            let mut altered = session.clone();
            altered.item_stakes[0].recipient = Some(session.participants[1].account.clone());
            assert!(validate_restored_items(&restored, &altered).is_err());
            altered = session.clone();
            altered.item_stakes[0].metadata_hash = Hash::new(b"changed metadata");
            assert!(validate_restored_items(&restored, &altered).is_err());
        }
    }
    #[test]
    fn expired_unstartable_item_lobby_returns_the_exact_nft_without_fungible_funding() {
        let (state, mut session, _) = payout_state(Quantity::zero());
        session.participants.truncate(1);
        session.stake = Quantity::zero();
        session.liability = Quantity::zero();
        session.phase = GamePhaseV1::Lobby;
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        reserve_fixture_item(&mut st, &mut session, 0);
        session.deadline_height = 0;
        save(&mut st, session.clone()).unwrap();
        ExpireGameSessionV1::new(session.session_id)
            .execute(&session.participants[0].account, &mut st)
            .unwrap();
        let closed = get(&st, &session.session_id).unwrap();
        assert_eq!(closed.phase, GamePhaseV1::Cancelled);
        assert!(closed.item_stakes[0].claimed);
        assert_eq!(
            st.world
                .nft(&closed.item_stakes[0].nft_id)
                .unwrap()
                .value()
                .owned_by,
            session.participants[0].account
        );
        assert!(st.world.game_account_references.iter().next().is_none());
    }
}
