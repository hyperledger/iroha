// Existing committed-journal test kept in its original test namespace.
#[test]
fn committed_event_journal_resolves_immutable_hashes_and_block_indexes() {
    let buyer = keypair(0x2A);
    let authority = account(&buyer);
    let mut state = state_with_accounts(&[&buyer]);
    let mut policy_digest = [0; 32];
    transact(&mut state, 1, NOW, |transaction| {
        policy_digest = activate_policy(transaction, &authority);
        Ok(())
    })
    .expect("commit policy block");
    let first = order(&buyer, 1);
    let second = order(&buyer, 2);
    transact(&mut state, 2, NOW + 1, |transaction| {
        SubmitSorafsOrderbookOrder::new(encode(&first), policy_digest)
            .execute(&authority, transaction)?;
        SubmitSorafsOrderbookOrder::new(encode(&second), policy_digest)
            .execute(&authority, transaction)
    })
    .expect("commit two-order block");
    let view = state.view();
    let page = FindSorafsOrderbookEvents::new(None, None, 10)
        .execute(&view)
        .expect("query committed event journal");
    assert_eq!(page.finalized_cursor.height, 2);
    assert_eq!(page.events.len(), 3);
    assert_eq!(
        page.events
            .iter()
            .map(|event| (event.sequence, event.block_height, event.event_index))
            .collect::<Vec<_>>(),
        vec![(1, 1, 0), (2, 2, 0), (3, 2, 1)]
    );
    let first_hash = *iroha_crypto::HashOf::new(&block_header_at(1, NOW)).as_ref();
    let second_hash = *iroha_crypto::HashOf::new(&block_header_at(2, NOW + 1)).as_ref();
    assert_eq!(page.events[0].block_hash, first_hash);
    assert_eq!(page.events[1].block_hash, second_hash);
    assert_eq!(page.events[2].block_hash, second_hash);
    assert_eq!(page.finalized_cursor.block_hash, second_hash);
    for (sequence, expected_height, expected_index) in [(1, 1, 0), (2, 2, 0), (3, 2, 1)] {
        let persisted = read_persisted_event(view.world(), sequence)
            .expect("read persisted event")
            .expect("persisted event exists");
        assert_eq!(persisted.sequence, sequence);
        assert_eq!(persisted.target_block_height, expected_height);
        assert_eq!(persisted.event_index, expected_index);
    }
    let stale_anchor = OrderbookFinalizedCursorV1 {
        height: 1,
        block_hash: first_hash,
    };
    assert_eq!(
        FindSorafsOrderbookEvents::new(Some(stale_anchor), None, 10).execute(&view),
        Err(QueryExecutionFail::Expired)
    );
}

#[test]
fn orderbook_durable_frames_preserve_authoritative_journal_position() {
    fn check<T>(
        world: &impl crate::state::WorldReadOnly,
        key: &StatePath,
        name: &str,
        decode: impl Fn(&[u8]) -> Result<T, InstructionExecutionError>,
    ) where
        T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
    {
        let bytes = world
            .smart_contract_state()
            .get(key)
            .expect("persisted owner frame");
        assert_eq!(T::nominal_name(), name);
        assert_eq!(T::frame_name(), name);
        let view = norito::core::from_bytes_view(bytes).expect("valid persisted envelope");
        assert_eq!(view.schema(), norito::schema::identity::frame_hash::<T>());
        let decoded = decode(bytes).expect("bounded production state decoder");
        assert_eq!(
            norito::encode_canonical(&decoded).expect("re-encode all fields"),
            *bytes
        );
        let mut substituted = bytes.clone();
        substituted[6..22]
            .copy_from_slice(&norito::schema::identity::frame_hash::<iroha_crypto::Hash>());
        assert!(matches!(
            norito::decode_canonical::<T>(&substituted),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(decode(&substituted).is_err());
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }
    let buyer = keypair(0x2A);
    let authority = account(&buyer);
    let mut state = state_with_accounts(&[&buyer]);
    let mut policy_digest = [0; 32];
    transact(&mut state, 1, NOW, |transaction| {
        policy_digest = activate_policy(transaction, &authority);
        Ok(())
    })
    .expect("commit orderbook policy");
    let request = order(&buyer, 1);
    transact(&mut state, 2, NOW + 1, |transaction| {
        SubmitSorafsOrderbookOrder::new(encode(&request), policy_digest)
            .execute(&authority, transaction)
    })
    .expect("commit signed order");
    let view = state.view();
    let world = view.world();
    let head = read_event_journal_head(world)
        .expect("journal head agrees with committed terminal event")
        .expect("journal head exists");
    let event = read_persisted_event(world, head.last_sequence)
        .expect("validated terminal event")
        .expect("terminal event exists");
    assert_eq!(event.target_block_height, 2);
    assert_eq!(event.event_index, head.last_event_index);
    check::<OrderbookPersistedEventV1>(
        world,
        &event_key(head.last_sequence),
        "iroha_core::smartcontracts::isi::sorafs_orderbook::OrderbookPersistedEventV1",
        |bytes| decode_state(bytes, "test persisted event"),
    );
    check::<OrderbookEventJournalHeadV1>(
        world,
        event_journal_head_key(),
        "iroha_core::smartcontracts::isi::sorafs_orderbook::OrderbookEventJournalHeadV1",
        |bytes| decode_state(bytes, "test journal head"),
    );
}
