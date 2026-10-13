type TailBatchOutcomes = BTreeMap<
    HashOf<TransactionEntrypoint>,
    Vec<iroha_data_model::events::data::prelude::AssetBatchTransferOutcome>,
>;

/// Attach executor-owned receipt rows without clearing already-complete outputs.
/// Validate every row before changing any result. No display-hash inference occurs here.
fn attach_fixture_receipts(
    results: &mut [iroha_data_model::transaction::signed::TransactionResult],
    owners: &BTreeMap<HashOf<TransactionEntrypoint>, usize>,
    outcomes: TailBatchOutcomes,
) -> Result<(), String> {
    let mut assigned = BTreeSet::new();
    for (owner, receipts) in &outcomes {
        let index = owners
            .get(owner)
            .ok_or_else(|| "batch receipt has no exact executed owner".to_owned())?;
        let result = results
            .get(*index)
            .ok_or_else(|| "batch receipt result position is out of range".to_owned())?;
        if !assigned.insert(*index) {
            return Err("batch receipts repeat one result position".into());
        }
        if receipts.is_empty() || !result.batch_transfer_outcomes().is_empty() {
            return Err("batch receipt competes with an existing output or is empty".into());
        }
    }
    for (owner, receipts) in outcomes {
        results[owners[&owner]].set_batch_transfer_outcomes(receipts);
    }
    Ok(())
}

/// Prefix identities are real network execution calls; reveal receipts use their
/// inner call. Canonical outer/inner uniqueness preserves the existing receipt gate.
fn fixture_network_receipt_owners(
    entries: &[TransactionEntrypoint],
) -> Result<BTreeMap<HashOf<TransactionEntrypoint>, usize>, String> {
    let mut identities = BTreeSet::new();
    for entry in entries {
        if !identities.insert(entry.hash()) {
            return Err("network prefix repeats a canonical receipt identity".into());
        }
    }
    let mut owners = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let call = entry.execution_call_hash();
        if matches!(entry, TransactionEntrypoint::SealedReveal(_)) && !identities.insert(call) {
            return Err("network prefix repeats a sealed receipt alias".into());
        }
        if owners.insert(call, index).is_some() {
            return Err("network prefix repeats an executed receipt owner".into());
        }
    }
    Ok(owners)
}

// Structural-only receipt mutation controls; execution custody is exercised by
// actual State output producer tests. This helper is never used by production.
fn join_time_fixture_receipts(
    prefix: &BTreeMap<HashOf<TransactionEntrypoint>, usize>,
    proposal: HashOf<BlockHeader>,
    invocations: &[iroha_data_model::block::execution_output::TimeInvocationV1],
    results: Vec<TransactionResultInner>,
    calls: &[Hash],
    receipts: TailBatchOutcomes,
) -> Result<Vec<iroha_data_model::transaction::TransactionResult>, String> {
    if invocations.len() != results.len() || invocations.len() != calls.len() {
        return Err("Time occurrence positions differ".into());
    }
    let mut owners = BTreeMap::new();
    for (index, (invocation, call)) in invocations.iter().zip(calls).enumerate() {
        if invocation.execution_call_hash(proposal)? != *call {
            return Err("Time call differs from its exact descriptor".into());
        }
        let call = HashOf::from_untyped_unchecked(*call);
        if prefix.contains_key(&call) || owners.insert(call, index).is_some() {
            return Err("Time call repeats another source".into());
        }
    }
    let mut rows: Vec<_> = results
        .into_iter()
        .map(iroha_data_model::transaction::TransactionResult::from)
        .collect();
    attach_fixture_receipts(&mut rows, &owners, receipts)?;
    Ok(rows)
}

// Private result ownership checks. Economic rows are additionally exercised by
// the real State/Kura independent-batch controls in ordinary_common_tail_tests.

fn tail_receipt_fixture() -> iroha_data_model::events::data::prelude::AssetBatchTransferOutcome {
    use iroha_data_model::events::data::prelude::{
        AssetBatchTransferLegStatus, AssetBatchTransferOutcome,
    };
    let (authority, _) = gen_account_in("tail");
    let definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("tail", "universal").unwrap(),
        "coin".parse().unwrap(),
    );
    AssetBatchTransferOutcome {
        leg_index: 0,
        leg_id: "owned".into(),
        asset: iroha_data_model::asset::AssetId::new(definition, authority.clone()),
        destination: authority,
        amount: 1u32.into(),
        status: AssetBatchTransferLegStatus::Applied,
    }
}

#[test]
fn common_tail_receipt_join_preserves_full_prefix_and_rejects_competing_rows_atomically() {
    use iroha_data_model::transaction::signed::TransactionResult;
    let first = HashOf::from_untyped_unchecked(Hash::new(b"first executed call"));
    let second = HashOf::from_untyped_unchecked(Hash::new(b"second executed call"));
    let owners = BTreeMap::from([(first, 0), (second, 1)]);
    let receipt = tail_receipt_fixture();
    let mut prefix = vec![TransactionResult::new(Ok(Vec::default())); 2];
    prefix[0].set_batch_transfer_outcomes(vec![receipt.clone()]);
    let retained = prefix[0].clone();
    attach_fixture_receipts(&mut prefix, &owners, BTreeMap::new()).unwrap();
    assert_eq!(prefix[0], retained);
    let before = prefix.clone();
    assert!(
        attach_fixture_receipts(
            &mut prefix,
            &owners,
            BTreeMap::from([
                (first, vec![receipt.clone()]),
                (second, vec![receipt.clone()]),
            ])
        )
        .is_err()
    );
    assert_eq!(
        prefix, before,
        "a later failure cannot attach any earlier row"
    );
    let mut empty = vec![TransactionResult::new(Ok(Vec::default()))];
    assert!(
        attach_fixture_receipts(
            &mut empty,
            &BTreeMap::from([(first, 0), (second, 0)]),
            BTreeMap::from([
                (first, vec![receipt.clone()]),
                (second, vec![receipt.clone()])
            ])
        )
        .is_err()
    );
    assert!(empty[0].batch_transfer_outcomes().is_empty());
    attach_fixture_receipts(
        &mut prefix,
        &owners,
        BTreeMap::from([(second, vec![receipt.clone()])]),
    )
    .unwrap();
    assert_eq!(prefix[0], retained);
    assert_eq!(prefix[1].batch_transfer_outcomes(), &[receipt]);
}

#[test]
fn common_tail_receipt_join_rejects_unknown_empty_and_out_of_range_owners() {
    use iroha_data_model::transaction::signed::TransactionResult;
    let owner = HashOf::from_untyped_unchecked(Hash::new(b"executed owner"));
    let receipt = tail_receipt_fixture();
    for (owners, outcomes) in [
        (
            BTreeMap::new(),
            BTreeMap::from([(owner, vec![receipt.clone()])]),
        ),
        (
            BTreeMap::from([(owner, 0)]),
            BTreeMap::from([(owner, Vec::new())]),
        ),
        (
            BTreeMap::from([(owner, 1)]),
            BTreeMap::from([(owner, vec![receipt])]),
        ),
    ] {
        let mut results = vec![TransactionResult::new(Ok(Vec::default()))];
        let before = results.clone();
        assert!(attach_fixture_receipts(&mut results, &owners, outcomes).is_err());
        assert_eq!(results, before);
    }
}

#[test]
fn time_receipts_bind_distinct_schedule_calls_of_the_same_action() {
    use iroha_data_model::block::execution_output::{TimeInvocationV1, TriggerUseV1};
    use iroha_data_model::events::time::{TimeEvent, TimeInterval};
    let proposal = HashOf::from_untyped_unchecked(Hash::new(b"Time fixture proposal"));
    let time = TimeInvocationV1 {
        schedule_index: 0,
        event: TimeEvent::new(TimeInterval {
            since_ms: 0,
            length_ms: 1,
        }),
        trigger: TriggerUseV1 {
            trigger_id: "repeat".parse().unwrap(),
            registered_at_height: 0,
            action_hash: Hash::new(b"same use-time action"),
        },
    };
    let mut second_invocation = time.clone();
    second_invocation.schedule_index = 1;
    let entries = vec![time, second_invocation];
    let calls = entries
        .iter()
        .map(|entry| entry.execution_call_hash(proposal).unwrap())
        .collect::<Vec<_>>();
    let first = tail_receipt_fixture();
    let mut second = first.clone();
    second.leg_id = "second invocation".into();
    let rows = BTreeMap::from([
        (
            HashOf::from_untyped_unchecked(calls[0]),
            vec![first.clone()],
        ),
        (
            HashOf::from_untyped_unchecked(calls[1]),
            vec![second.clone()],
        ),
    ]);
    let inner = vec![Ok(Vec::default()); 2];
    let full = join_time_fixture_receipts(
        &BTreeMap::new(),
        proposal,
        &entries,
        inner.clone(),
        &calls,
        rows.clone(),
    )
    .unwrap();
    assert_eq!(full[0].batch_transfer_outcomes(), &[first]);
    assert_eq!(full[1].batch_transfer_outcomes(), &[second]);
    assert_eq!(entries[0].trigger, entries[1].trigger);
    assert_ne!(entries[0].schedule_index, entries[1].schedule_index);
    assert_ne!(calls[0], calls[1]);
    assert!(
        join_time_fixture_receipts(
            &BTreeMap::new(),
            proposal,
            &entries[..1],
            inner.clone(),
            &calls,
            rows.clone()
        )
        .is_err()
    );
    let mut wrong_descriptor = entries.clone();
    wrong_descriptor[0].trigger.action_hash = Hash::new(b"not that Time action");
    assert!(
        join_time_fixture_receipts(
            &BTreeMap::new(),
            proposal,
            &wrong_descriptor,
            inner.clone(),
            &calls,
            rows.clone()
        )
        .is_err()
    );
    assert!(
        join_time_fixture_receipts(
            &BTreeMap::new(),
            proposal,
            &entries,
            inner.clone(),
            &[calls[0]; 2],
            rows.clone()
        )
        .is_err()
    );
    let prefix = BTreeMap::from([(HashOf::from_untyped_unchecked(calls[0]), 0)]);
    assert!(
        join_time_fixture_receipts(
            &prefix,
            proposal,
            &entries,
            inner.clone(),
            &calls,
            rows.clone()
        )
        .is_err()
    );
    let mut leftovers = rows;
    leftovers.insert(
        HashOf::from_untyped_unchecked(Hash::new(b"unowned callback")),
        vec![tail_receipt_fixture()],
    );
    assert!(
        join_time_fixture_receipts(
            &BTreeMap::new(),
            proposal,
            &entries,
            inner,
            &calls,
            leftovers
        )
        .is_err()
    );
}

#[test]
fn common_tail_prefix_receipt_aliases_are_one_to_one() {
    use iroha_data_model::transaction::signed::SealedTransactionReveal;
    let (authority, key) = gen_account_in("tail");
    let signed = iroha_data_model::transaction::TransactionBuilder::new(
        iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"tail network",
        ))),
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "tail".into(),
    )])
    .sign(key.private_key());
    let external = TransactionEntrypoint::External(signed.clone());
    let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        Hash::new(b"commitment"),
        signed,
        [0; 32],
    ));
    assert_eq!(
        fixture_network_receipt_owners(std::slice::from_ref(&reveal))
            .unwrap()
            .get(&external.execution_call_hash()),
        Some(&0)
    );
    assert!(fixture_network_receipt_owners(&[external.clone(), external.clone()]).is_err());
    assert!(fixture_network_receipt_owners(&[external, reveal]).is_err());
}
