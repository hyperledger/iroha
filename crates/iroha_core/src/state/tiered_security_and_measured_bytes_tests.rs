use iroha_data_model::nexus::{
    AxtAnchoredSpendReplayKeyV1, AxtHandleReplayKey, AxtPolicyEntry, AxtReplayRecord,
    AxtSourceTransferReplayKeyV1, AxtSourceTransferReplayRecordV1, AxtSpendNonceV1,
};

#[test]
fn tiered_collection_requires_only_json_and_resident_measurement_for_values() {
    #[derive(norito::derive::JsonSerialize)]
    struct JsonOnlyValue {
        label: String,
    }
    impl MeasuredBytes for JsonOnlyValue {
        fn measured_bytes(&self) -> usize {
            std::mem::size_of::<Self>() + self.label.capacity()
        }
    }
    let key = iroha_test_samples::ALICE_ID.clone();
    let handle = TieredKeyHandle::Account(key.clone());
    let mut backend = TieredStateBackend::default();
    let mut scores = Vec::new();
    let mut seen = BTreeSet::new();
    let mut context = CollectContext {
        snapshot_idx: 1,
        scores: &mut scores,
        seen: &mut seen,
    };
    let mut value = JsonOnlyValue {
        label: "first".to_owned(),
    };
    backend
        .collect_entry(TieredSegment::Accounts, &handle, &key, &value, &mut context)
        .unwrap();
    let metadata = backend.entries.values().next().unwrap();
    assert_eq!(
        metadata.last_value_hash,
        compute_json_hash(&value).unwrap().0
    );
    assert_eq!(
        metadata.value_size_bytes,
        MeasuredBytes::measured_bytes(&value)
    );
    assert_eq!(metadata.last_mutated_snapshot, 1);
    let key_bytes = norito::codec::Encode::encode(&key);
    assert_eq!(
        backend.entry_keys.values().next().unwrap().key_encoded,
        key_bytes
    );

    context.snapshot_idx = 2;
    backend
        .collect_entry_with_encoded_key(
            TieredSegment::Accounts,
            &handle,
            key_bytes.clone(),
            &value,
            &mut context,
        )
        .unwrap();
    let metadata = backend.entries.values().next().unwrap();
    assert_eq!(metadata.last_present_snapshot, 2);
    assert_eq!(metadata.last_mutated_snapshot, 1);

    value.label.push_str(" changed");
    context.snapshot_idx = 3;
    backend
        .collect_entry_with_encoded_key(
            TieredSegment::Accounts,
            &handle,
            key_bytes,
            &value,
            &mut context,
        )
        .unwrap();
    let metadata = backend.entries.values().next().unwrap();
    assert_eq!(
        metadata.last_value_hash,
        compute_json_hash(&value).unwrap().0
    );
    assert_eq!(
        metadata.value_size_bytes,
        MeasuredBytes::measured_bytes(&value)
    );
    assert_eq!(metadata.last_present_snapshot, 3);
    assert_eq!(metadata.last_mutated_snapshot, 3);
    assert_eq!(backend.entries.len(), 1);
    assert_eq!(context.seen.len(), 1);
    assert_eq!(context.scores.len(), 3);
}

type AxtSecurityMapFixture = (
    DataSpaceId,
    AxtHandleCounterRecord,
    AssetDefinitionId,
    AxtAssetIncarnationV1,
    AxtHandleBudgetKey,
    AxtHandleBudgetRecord,
);

fn axt_security_map_fixture_with_scope(scope: String) -> AxtSecurityMapFixture {
    let definition_id = AssetDefinitionId::from_uuid_bytes([
        0x41, 0x63, 0x85, 0xa7, 0xc9, 0xeb, 0x4d, 0xef, 0x80, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86,
        0x97,
    ])
    .expect("tiered AXT security-map fixture UUID is valid");
    let default_context = AxtHandleIssuerContextV1::default();
    let registration_header = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"tiered AXT security-map registration",
    ));
    let incarnation = AxtAssetIncarnationV1::derive(
        &default_context.network_id,
        &definition_id,
        &registration_header,
        &Hash::new(b"tiered AXT security-map execution"),
        0,
    );
    let context = AxtHandleIssuerContextV1 {
        asset_definition_incarnation: incarnation,
        ..default_context
    };
    let payload = AssetHandleIssuerPayloadV1 {
        context,
        asset_definition_id: definition_id.clone(),
        scope: vec![scope],
        subject: HandleSubject {
            account: "tiered-axt-security-subject".to_owned(),
            origin_dsid: Some(context.asset_dsid),
        },
        budget: HandleBudget {
            remaining: Quantity::from(11_u64),
            per_use: None,
        },
        active_handle_era: 9,
        next_handle_counter: 4,
        group_binding: GroupBinding {
            composability_group_id: b"tiered-axt-security".to_vec(),
            epoch_id: 5,
        },
        target_lane: LaneId::SINGLE,
        axt_binding: AxtBinding::new([0xC7; 32]),
        manifest_view_root: [0xD7; 32],
        expiry_slot: 101,
        max_clock_skew_ms: None,
    };
    let budget_key = AxtHandleBudgetKey::from_issuer_payload_v1(&payload);
    let mut budget_record = AxtHandleBudgetRecord::empty();
    budget_record
        .try_consume(&budget_key, &Quantity::from(4_u64), 101)
        .expect("tiered AXT family consumption fits its signed budget");
    (
        context.asset_dsid,
        AxtHandleCounterRecord::try_from_parts(
            payload.next_handle_counter,
            payload.active_handle_era,
        )
        .expect("tiered AXT counter fixture is canonical"),
        definition_id,
        incarnation,
        budget_key,
        budget_record,
    )
}
fn axt_security_map_fixture() -> AxtSecurityMapFixture {
    axt_security_map_fixture_with_scope("transfer".to_owned())
}
fn axt_policy_replay_fixture(
    scope: String,
) -> (
    DataSpaceId,
    AxtPolicyEntry,
    AxtHandleReplayKey,
    AxtReplayRecord,
    AxtHandleBudgetRecord,
) {
    let (dataspace, _, _, incarnation, budget_key, budget_record) =
        axt_security_map_fixture_with_scope(scope);
    let policy = AxtPolicyEntry {
        manifest_root: [0xD7; 32],
        target_lane: LaneId::SINGLE,
        active_handle_era: 9,
        next_handle_counter: 5,
        current_slot: 101,
    };
    let replay_key = AxtHandleReplayKey::from_parts(
        dataspace,
        incarnation,
        [0xC7; 32],
        policy.active_handle_era,
        4,
        policy.target_lane,
    );
    let replay = AxtReplayRecord {
        dataspace,
        budget_key,
        used_slot: 100,
        retain_until_slot: 101,
    };
    replay
        .validate_for_key(&replay_key)
        .expect("tiered AXT replay fixture is canonical");
    (dataspace, policy, replay_key, replay, budget_record)
}
#[test]
fn streamed_hash_matches_canonical_json() {
    let value: norito::json::Value = norito::json::from_str(
        r#"{
                "domain": "wonderland",
                "accounts": [
                    {"id": "i105-subject-alice", "metadata": {"email": "alice@example.com"}},
                    {"id": "i105-subject-bob", "metadata": {"roles": ["admin", "auditor"]}}
                ],
                "supply": 42,
                "flags": {
                    "enabled": true,
                    "threshold": 0.5
                }
            }"#,
    )
    .expect("valid JSON fixture");
    let (stream_hash, stream_len) = compute_json_hash(&value).expect("streamed hash computation");
    let encoded = norito::json::to_vec(&value).expect("direct encode");
    assert_eq!(stream_len, encoded.len());
    assert_eq!(stream_hash, sha256(&encoded));
}
#[test]
fn hot_bytes_account_for_vec_capacity() {
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&[1_u8, 2, 3, 4, 5, 6, 7, 8]);
    let expected = std::mem::size_of::<Vec<u8>>() + value.capacity() * std::mem::size_of::<u8>();
    let measured = compute_hot_bytes(&value).expect("hot byte measurement");
    assert_eq!(measured, expected);
}
#[test]
fn measured_bytes_cover_both_domain_id_labels() {
    use iroha_model_base::domain::DomainId;

    for (name, dataspace) in [("a", "b"), ("treasury", "b"), ("a", "centralbank")] {
        let id = DomainId::try_new(name, dataspace).expect("canonical domain labels");
        assert_eq!(
            MeasuredBytes::measured_bytes(&id),
            std::mem::size_of::<DomainId>() + name.len() + dataspace.len(),
            "both independently sized domain labels must be accounted for"
        );
    }
}
#[test]
fn measured_bytes_account_for_proof_attachment_list_capacity() {
    let attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![0xCA, 0xFE]),
        VerifyingKeyId::new("halo2/ipa", "tiered-capacity-fixture"),
    );
    let compact = vec![attachment.clone()];
    let mut reserved = Vec::with_capacity(8);
    reserved.push(attachment);
    let compact = ProofAttachmentList::try_from(compact).expect("valid compact list");
    let reserved = ProofAttachmentList::try_from(reserved).expect("valid reserved list");
    assert_eq!(compact.as_slice(), reserved.as_slice());
    let capacity_delta = reserved
        .capacity()
        .checked_sub(compact.capacity())
        .expect("reserved fixture has greater capacity");
    assert!(capacity_delta > 0);
    let measured_delta = MeasuredBytes::measured_bytes(&reserved)
        .checked_sub(MeasuredBytes::measured_bytes(&compact))
        .expect("reserved fixture has greater measured size");
    assert_eq!(
        measured_delta,
        capacity_delta.saturating_mul(std::mem::size_of::<ProofAttachment>())
    );
}
#[test]
fn measured_bytes_cover_trigger_filters() {
    use iroha_data_model::{
        events::{EventFilterBox, data::DataEventFilter},
        trigger::{TriggerId, action::Repeats},
    };
    let trigger_id: TriggerId = "audit_trigger".parse().expect("trigger id");
    let repeats = Repeats::Exactly(1);
    let filter = EventFilterBox::Data(DataEventFilter::Any);
    assert!(MeasuredBytes::measured_bytes(&trigger_id) >= std::mem::size_of::<TriggerId>());
    assert_eq!(
        MeasuredBytes::measured_bytes(&repeats),
        std::mem::size_of::<Repeats>()
    );
    assert!(MeasuredBytes::measured_bytes(&filter) >= std::mem::size_of::<EventFilterBox>());
}
#[test]
fn measured_bytes_cover_opaque_account_id() {
    let opaque = OpaqueAccountId::from_hash(Hash::new([7_u8; 32]));
    assert_eq!(
        MeasuredBytes::measured_bytes(&opaque),
        std::mem::size_of::<OpaqueAccountId>()
    );
}
#[test]
fn measured_bytes_cover_opaque_asset_definition_id() {
    use iroha_data_model::asset::AssetDefinitionId;
    let opaque = AssetDefinitionId::from_uuid_bytes([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x4d, 0xef, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77,
    ])
    .expect("measured-bytes fixture UUID is valid");
    assert_eq!(
        MeasuredBytes::measured_bytes(&opaque),
        std::mem::size_of::<AssetDefinitionId>()
    );
}
#[test]
fn axt_replay_measured_bytes_include_dynamic_family_heap() {
    let (_, _, _, short, _) = axt_policy_replay_fixture("x".to_owned());
    let (_, _, _, long, _) = axt_policy_replay_fixture("x".repeat(512));
    for record in [&short, &long] {
        assert_eq!(
            MeasuredBytes::measured_bytes(record),
            std::mem::size_of::<AxtReplayRecord>()
                .saturating_add(record.budget_key.allocated_heap_bytes())
        );
    }
    assert!(long.budget_key.allocated_heap_bytes() > short.budget_key.allocated_heap_bytes());
    assert!(MeasuredBytes::measured_bytes(&long) > MeasuredBytes::measured_bytes(&short));
}
#[test]
fn hot_budget_arithmetic_is_saturating_and_overflow_safe() {
    let widened_usize = u64::try_from(usize::MAX).unwrap_or(u64::MAX);
    assert_eq!(
        hot_budget_bytes(usize::MAX, 1),
        widened_usize.saturating_add(1)
    );
    assert!(hot_budget_has_capacity(u64::MAX - 1, 1, u64::MAX));
    assert!(!hot_budget_has_capacity(u64::MAX - 1, 2, u64::MAX));
    assert!(hot_budget_has_capacity(u64::MAX, u64::MAX, 0));
}
#[test]
fn axt_budget_keys_participate_in_the_hot_byte_limit() {
    let (_, _, _, _, short_key, short_record) = axt_security_map_fixture_with_scope("x".to_owned());
    let (_, _, _, _, long_key, long_record) = axt_security_map_fixture_with_scope("x".repeat(512));
    let entry_budget = |key: &AxtHandleBudgetKey, record: &AxtHandleBudgetRecord| {
        hot_budget_bytes(
            norito::codec::Encode::encode(key).len(),
            MeasuredBytes::measured_bytes(record),
        )
    };
    let short_budget = entry_budget(&short_key, &short_record);
    let long_budget = entry_budget(&long_key, &long_record);
    assert!(long_budget > short_budget);

    let temp = tempdir().expect("temporary tiered AXT hot-budget directory");
    for (label, key, record, expected_hot) in [
        ("short", short_key, short_record, true),
        ("long", long_key, long_record, false),
    ] {
        let key_payload = norito::codec::Encode::encode(&key);
        let value_size = MeasuredBytes::measured_bytes(&record);
        let expected_budget = hot_budget_bytes(key_payload.len(), value_size);
        let mut world = World::default();
        world.axt_handle_budget_ledger.insert(key, record);
        let mut backend = TieredStateBackend::new(
            true,
            0,
            short_budget,
            0,
            Some(temp.path().join(label)),
            None,
            0,
            0,
        );
        backend
            .record_world_snapshot(&world)
            .expect("record tiered AXT hot-budget snapshot");
        let manifest = backend.last_manifest().expect("tiered manifest recorded");
        let entry = manifest
            .hot_entries
            .iter()
            .chain(&manifest.cold_entries)
            .find(|entry| entry.key_payload == key_payload)
            .expect("AXT budget entry is present");
        assert_eq!(entry.value_size_bytes(), value_size);
        assert_eq!(entry.hot_budget_bytes(), expected_budget);
        assert_eq!(manifest.hot_entries.len() == 1, expected_hot);
        assert_eq!(manifest.cold_entries.len() == 1, !expected_hot);
    }
}
#[test]
fn axt_policy_and_replay_roundtrip_through_persisted_cold_manifest() {
    let (dataspace, policy, replay_key, replay, budget_record) =
        axt_policy_replay_fixture("cold-manifest".to_owned());
    assert_eq!(
        MeasuredBytes::measured_bytes(&policy),
        std::mem::size_of::<AxtPolicyEntry>()
    );
    let mut world = World::default();
    world.axt_policies.insert(dataspace, policy);
    world.axt_replay_ledger.insert(replay_key, replay.clone());
    world
        .axt_handle_budget_ledger
        .insert(replay.budget_key.clone(), budget_record);

    let temp = tempdir().expect("temporary tiered AXT policy/replay directory");
    let root = temp.path().to_path_buf();
    let mut backend = TieredStateBackend::new(true, 0, 1, 0, Some(root.clone()), None, 0, 0);
    backend
        .record_world_snapshot(&world)
        .expect("persist tiered AXT policy and replay ledger");
    let snapshot_index = backend
        .last_manifest()
        .expect("tiered manifest recorded")
        .snapshot_index;
    drop(backend);

    let manifest_text = fs::read_to_string(
        root.join(format!("{snapshot_index:020}"))
            .join("manifest.json"),
    )
    .expect("read persisted tiered AXT manifest");
    assert!(manifest_text.contains(r#""axt_policies""#));
    assert!(manifest_text.contains(r#""axt_replay_ledger""#));
    let manifest: TieredSnapshotManifest =
        json::from_str(&manifest_text).expect("decode persisted tiered AXT manifest");
    let policy_entry = manifest
        .cold_entries
        .iter()
        .find(|entry| entry.segment == TieredSegment::AxtPolicies)
        .expect("AXT policy is persisted in the cold manifest");
    let replay_entry = manifest
        .cold_entries
        .iter()
        .find(|entry| entry.segment == TieredSegment::AxtReplayLedger)
        .expect("AXT replay record is persisted in the cold manifest");
    assert_eq!(
        policy_entry.key_payload,
        norito::codec::Encode::encode(&dataspace)
    );
    assert_eq!(
        replay_entry.key_payload,
        norito::codec::Encode::encode(&replay_key)
    );
    assert_eq!(
        policy_entry.value_size_bytes(),
        MeasuredBytes::measured_bytes(&policy)
    );
    assert_eq!(
        replay_entry.value_size_bytes(),
        MeasuredBytes::measured_bytes(&replay)
    );

    let reader = TieredStateBackend::new(true, 0, 1, 0, Some(root), None, 0, 0);
    let policy_bytes = reader
        .read_cold_payload(snapshot_index, policy_entry)
        .expect("read AXT policy cold payload")
        .expect("AXT policy cold payload exists");
    let replay_bytes = reader
        .read_cold_payload(snapshot_index, replay_entry)
        .expect("read AXT replay cold payload")
        .expect("AXT replay cold payload exists");
    assert_eq!(
        json::from_slice::<AxtPolicyEntry>(&policy_bytes).expect("decode AXT policy payload"),
        policy
    );
    assert_eq!(
        json::from_slice::<AxtReplayRecord>(&replay_bytes).expect("decode AXT replay payload"),
        replay
    );
}
#[test]
fn anchored_axt_spend_nonce_persists_in_tiered_manifest_and_removal_diff() {
    let key = AxtAnchoredSpendReplayKeyV1 {
        issuer_context: AxtHandleIssuerContextV1::default(),
        nonce: AxtSpendNonceV1::try_new([0x9B; 32]).expect("nonzero nonce"),
    };
    let source = AxtSourceTransferReplayKeyV1 {
        network_id: key.issuer_context.network_id,
        dataspace_id: key.issuer_context.asset_dsid,
        lane_id: LaneId::SINGLE,
        block_header_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"tiered AXT source transfer",
        )),
        source_tx_index: 1,
        transcript_index: 2,
        delta_index: 3,
    };
    let source_record = AxtSourceTransferReplayRecordV1 {
        issuer_nonce: key,
        consumed_slot: 42,
    };
    let mut world = World::default();
    world.axt_spend_nonce_ledger.insert(key, 42);
    world
        .axt_source_transfer_replay_ledger
        .insert(source, source_record);
    let temp = tempdir().expect("temporary tiered spend nonce directory");
    let mut backend =
        TieredStateBackend::new(true, 0, 1, 0, Some(temp.path().to_path_buf()), None, 0, 0);
    backend
        .record_world_snapshot(&world)
        .expect("persist spend nonce snapshot");
    let manifest = backend.last_manifest().expect("tiered manifest recorded");
    let entry = manifest
        .cold_entries
        .iter()
        .find(|entry| entry.segment == TieredSegment::AxtSpendNonceLedger)
        .expect("permanent spend nonce is present");
    assert_eq!(entry.key_payload, norito::codec::Encode::encode(&key));
    let payload = backend
        .read_cold_payload(manifest.snapshot_index, entry)
        .expect("read spend nonce cold payload")
        .expect("spend nonce payload exists");
    assert_eq!(
        json::from_slice::<u64>(&payload).expect("decode spend slot"),
        42
    );
    let source_entry = manifest
        .cold_entries
        .iter()
        .find(|entry| entry.segment == TieredSegment::AxtSourceTransferReplayLedger)
        .expect("permanent source transfer is present");
    assert_eq!(
        source_entry.key_payload,
        norito::codec::Encode::encode(&source)
    );
    let source_payload = backend
        .read_cold_payload(manifest.snapshot_index, source_entry)
        .expect("read source transfer cold payload")
        .expect("source transfer payload exists");
    assert_eq!(
        json::from_slice::<AxtSourceTransferReplayRecordV1>(&source_payload)
            .expect("decode source transfer replay record"),
        source_record
    );

    let mut removed = world.block();
    assert_eq!(removed.axt_spend_nonce_ledger.remove(key), Some(42));
    assert_eq!(
        removed.axt_source_transfer_replay_ledger.remove(source),
        Some(source_record)
    );
    assert!(
        removed
            .tiered_snapshot_diff()
            .entries()
            .iter()
            .any(|entry| matches!(entry, TieredKeyHandle::AxtSpendNonce(id) if *id == key))
    );
    assert!(removed.tiered_snapshot_diff().entries().iter().any(
        |entry| matches!(entry, TieredKeyHandle::AxtSourceTransferReplay(id) if *id == source)
    ));
}
#[test]
fn axt_policy_and_replay_block_payloads_update_and_remove_entries() {
    let (dataspace, policy, replay_key, replay, budget_record) =
        axt_policy_replay_fixture("incremental".to_owned());
    let mut world = World::default();
    world.axt_policies.insert(dataspace, policy);
    world.axt_replay_ledger.insert(replay_key, replay.clone());
    world
        .axt_handle_budget_ledger
        .insert(replay.budget_key.clone(), budget_record);
    let temp = tempdir().expect("temporary incremental AXT policy/replay directory");
    let mut backend =
        TieredStateBackend::new(true, 0, 1, 0, Some(temp.path().to_path_buf()), None, 0, 0);
    backend
        .record_world_snapshot(&world)
        .expect("seed tiered AXT policy and replay ledger");

    let updated_policy = AxtPolicyEntry {
        next_handle_counter: policy.next_handle_counter.saturating_add(1),
        current_slot: 202,
        ..policy
    };
    let updated_replay = AxtReplayRecord {
        used_slot: replay.used_slot.saturating_add(1),
        retain_until_slot: 202,
        ..replay.clone()
    };
    updated_replay
        .validate_for_key(&replay_key)
        .expect("updated tiered replay record is canonical");
    let mut update = world.block();
    update.axt_policies.insert(dataspace, updated_policy);
    update
        .axt_replay_ledger
        .insert(replay_key, updated_replay.clone());
    let diff = update.tiered_snapshot_diff();
    assert!(
        diff.entries()
            .iter()
            .any(|entry| matches!(entry, TieredKeyHandle::AxtPolicy(key) if *key == dataspace))
    );
    assert!(
        diff.entries()
            .iter()
            .any(|entry| matches!(entry, TieredKeyHandle::AxtReplay(key) if *key == replay_key))
    );
    let payload = update.tiered_snapshot_payload();
    drop(update);
    backend
        .record_world_snapshot_with_payload(&payload)
        .expect("persist incremental AXT policy and replay updates");

    let manifest = backend
        .last_manifest()
        .expect("updated tiered manifest recorded")
        .clone();
    let policy_entry = manifest
        .cold_entries
        .iter()
        .find(|entry| entry.segment == TieredSegment::AxtPolicies)
        .expect("updated AXT policy remains in the cold manifest");
    let replay_entry = manifest
        .cold_entries
        .iter()
        .find(|entry| entry.segment == TieredSegment::AxtReplayLedger)
        .expect("updated AXT replay remains in the cold manifest");
    let policy_bytes = backend
        .read_cold_payload(manifest.snapshot_index, policy_entry)
        .expect("read updated AXT policy cold payload")
        .expect("updated AXT policy cold payload exists");
    let replay_bytes = backend
        .read_cold_payload(manifest.snapshot_index, replay_entry)
        .expect("read updated AXT replay cold payload")
        .expect("updated AXT replay cold payload exists");
    assert_eq!(
        json::from_slice::<AxtPolicyEntry>(&policy_bytes).expect("decode updated AXT policy"),
        updated_policy
    );
    assert_eq!(
        json::from_slice::<AxtReplayRecord>(&replay_bytes).expect("decode updated AXT replay"),
        updated_replay
    );

    let mut removal = world.block();
    assert_eq!(removal.axt_policies.remove(dataspace), Some(policy));
    assert_eq!(removal.axt_replay_ledger.remove(replay_key), Some(replay));
    let payload = removal.tiered_snapshot_payload();
    drop(removal);
    backend
        .record_world_snapshot_with_payload(&payload)
        .expect("persist AXT policy and replay removals");
    let manifest = backend
        .last_manifest()
        .expect("AXT removal manifest recorded");
    assert!(
        manifest
            .hot_entries
            .iter()
            .chain(&manifest.cold_entries)
            .all(|entry| !matches!(
                entry.segment,
                TieredSegment::AxtPolicies | TieredSegment::AxtReplayLedger
            ))
    );
}
#[test]
fn axt_security_maps_roundtrip_through_tiered_payloads_with_exact_sizes() {
    let (dataspace, counter, definition_id, incarnation, budget_key, budget_record) =
        axt_security_map_fixture();
    assert_eq!(
        MeasuredBytes::measured_bytes(&counter),
        std::mem::size_of::<AxtHandleCounterRecord>()
    );
    assert_eq!(
        MeasuredBytes::measured_bytes(&incarnation),
        std::mem::size_of::<AxtAssetIncarnationV1>()
    );
    assert_eq!(
        MeasuredBytes::measured_bytes(&budget_record),
        std::mem::size_of::<AxtHandleBudgetRecord>()
            .saturating_add(budget_record.consumed().measured_bytes_extra())
    );
    let mut world = World::default();
    world.axt_handle_counters.insert(dataspace, counter);
    world
        .axt_asset_incarnations
        .insert(definition_id.clone(), incarnation);
    world
        .axt_handle_budget_ledger
        .insert(budget_key.clone(), budget_record.clone());

    let temp = tempdir().expect("temporary tiered AXT payload directory");
    let mut backend =
        TieredStateBackend::new(true, 0, 1, 0, Some(temp.path().to_path_buf()), None, 0, 0);
    backend
        .record_world_snapshot(&world)
        .expect("persist tiered AXT security maps");
    let manifest = backend.last_manifest().expect("tiered manifest recorded");
    let snapshot_index = manifest.snapshot_index;

    let counter_entry = manifest
        .cold_entries
        .iter()
        .find(|entry| entry.segment == TieredSegment::AxtHandleCounters)
        .expect("AXT counter is accounted in the tiered manifest");
    let incarnation_entry = manifest
        .cold_entries
        .iter()
        .find(|entry| entry.segment == TieredSegment::AxtAssetIncarnations)
        .expect("AXT asset incarnation is accounted in the tiered manifest");
    let budget_entry = manifest
        .cold_entries
        .iter()
        .find(|entry| entry.segment == TieredSegment::AxtHandleBudgetLedger)
        .expect("AXT family budget is accounted in the tiered manifest");

    assert_eq!(
        counter_entry.key_payload,
        norito::codec::Encode::encode(&dataspace)
    );
    assert_eq!(
        incarnation_entry.key_payload,
        norito::codec::Encode::encode(&definition_id)
    );
    assert_eq!(
        budget_entry.key_payload,
        norito::codec::Encode::encode(&budget_key)
    );
    assert_eq!(
        counter_entry.value_size_bytes(),
        MeasuredBytes::measured_bytes(&counter)
    );
    assert_eq!(
        incarnation_entry.value_size_bytes(),
        MeasuredBytes::measured_bytes(&incarnation)
    );
    assert_eq!(
        budget_entry.value_size_bytes(),
        MeasuredBytes::measured_bytes(&budget_record)
    );

    let counter_bytes = backend
        .read_cold_payload(snapshot_index, counter_entry)
        .expect("read AXT counter cold payload")
        .expect("AXT counter cold payload exists");
    let incarnation_bytes = backend
        .read_cold_payload(snapshot_index, incarnation_entry)
        .expect("read AXT incarnation cold payload")
        .expect("AXT incarnation cold payload exists");
    let budget_bytes = backend
        .read_cold_payload(snapshot_index, budget_entry)
        .expect("read AXT budget cold payload")
        .expect("AXT budget cold payload exists");
    assert_eq!(
        json::from_slice::<AxtHandleCounterRecord>(&counter_bytes)
            .expect("decode AXT counter payload"),
        counter
    );
    assert_eq!(
        json::from_slice::<AxtAssetIncarnationV1>(&incarnation_bytes)
            .expect("decode AXT incarnation payload"),
        incarnation
    );
    assert_eq!(
        json::from_slice::<AxtHandleBudgetRecord>(&budget_bytes)
            .expect("decode AXT budget payload"),
        budget_record
    );
}
#[test]
fn axt_security_maps_roundtrip_through_incremental_payloads() {
    let (dataspace, counter, definition_id, incarnation, budget_key, budget_record) =
        axt_security_map_fixture();
    let mut world = World::default();
    world.axt_handle_counters.insert(dataspace, counter);
    world
        .axt_asset_incarnations
        .insert(definition_id.clone(), incarnation);
    world
        .axt_handle_budget_ledger
        .insert(budget_key.clone(), budget_record.clone());

    let temp = tempdir().expect("temporary incremental AXT payload directory");
    let mut backend =
        TieredStateBackend::new(true, 0, 1, 0, Some(temp.path().to_path_buf()), None, 0, 0);
    backend
        .record_world_snapshot(&world)
        .expect("seed tiered AXT security maps");

    let updated_counter = AxtHandleCounterRecord::try_from_parts(5, 9)
        .expect("updated tiered counter fixture is canonical");
    let default_context = AxtHandleIssuerContextV1::default();
    let updated_incarnation = AxtAssetIncarnationV1::derive(
        &default_context.network_id,
        &definition_id,
        &HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"updated tiered AXT registration",
        )),
        &Hash::new(b"updated tiered AXT execution"),
        1,
    );
    let mut updated_budget = budget_record;
    updated_budget
        .try_consume(&budget_key, &Quantity::from(1_u64), 102)
        .expect("updated tiered consumption fits its signed budget");
    let mut block = world.block();
    block.axt_handle_counters.insert(dataspace, updated_counter);
    block
        .axt_asset_incarnations
        .insert(definition_id, updated_incarnation);
    block
        .axt_handle_budget_ledger
        .insert(budget_key, updated_budget.clone());
    let payload = block.tiered_snapshot_payload();
    backend
        .record_world_snapshot_with_payload(&payload)
        .expect("persist incremental AXT security-map payloads");

    let manifest = backend.last_manifest().expect("tiered manifest recorded");
    let snapshot_index = manifest.snapshot_index;
    let payload_for = |segment| {
        let entry = manifest
            .cold_entries
            .iter()
            .find(|entry| entry.segment == segment)
            .expect("updated AXT entry is present in the cold manifest");
        backend
            .read_cold_payload(snapshot_index, entry)
            .expect("read updated AXT cold payload")
            .expect("updated AXT cold payload exists")
    };
    assert_eq!(
        json::from_slice::<AxtHandleCounterRecord>(&payload_for(TieredSegment::AxtHandleCounters))
            .expect("decode updated AXT counter"),
        updated_counter
    );
    assert_eq!(
        json::from_slice::<AxtAssetIncarnationV1>(&payload_for(
            TieredSegment::AxtAssetIncarnations
        ))
        .expect("decode updated AXT incarnation"),
        updated_incarnation
    );
    assert_eq!(
        json::from_slice::<AxtHandleBudgetRecord>(&payload_for(
            TieredSegment::AxtHandleBudgetLedger
        ))
        .expect("decode updated AXT budget"),
        updated_budget
    );
}
fn dummy_state_entry(seed: u8) -> (StatePath, Vec<u8>) {
    (
        format!("tiered_state_{seed}")
            .parse()
            .expect("valid tiered-state fixture path"),
        vec![seed; usize::from(seed).saturating_add(2)],
    )
}
#[test]
fn hot_grace_allows_key_and_byte_budget_overflow_for_previous_entries() {
    let temp = tempdir().expect("tmpdir");
    let root = temp.path().to_path_buf();
    let mut backend = TieredStateBackend::new(true, 2, 0, 1, Some(root.clone()), None, 0, 0);
    let mut world = World::default();
    let (key1, value1) = dummy_state_entry(1);
    let (key2, value2) = dummy_state_entry(2);
    world.smart_contract_state.insert(key1, value1);
    world.smart_contract_state.insert(key2, value2);
    backend
        .record_world_snapshot(&world)
        .expect("first snapshot");
    let initial_hot_bytes = backend
        .last_manifest()
        .expect("initial manifest recorded")
        .hot_entries
        .iter()
        .fold(0_u64, |total, entry| {
            total.saturating_add(entry.hot_budget_bytes())
        });
    assert!(initial_hot_bytes > 1);
    backend.reconfigure(true, 1, initial_hot_bytes - 1, 1, Some(root), None, 0, 0);
    backend
        .record_world_snapshot(&world)
        .expect("second snapshot");
    let manifest = backend.last_manifest().expect("manifest recorded");
    assert_eq!(manifest.hot_entries.len(), 2);
    assert_eq!(manifest.hot_budget_overflow_keys, 1);
    assert_eq!(manifest.hot_budget_overflow_bytes, 1);
}
#[test]
fn incremental_snapshot_reports_unspillable_hot_byte_overflow() {
    let temp = tempdir().expect("tmpdir");
    let root = temp.path().to_path_buf();
    let mut backend = TieredStateBackend::new(true, 1, 0, 0, Some(root.clone()), None, 0, 0);
    let mut world = World::default();
    let (old_key, old_value) = dummy_state_entry(1);
    let old_handle = TieredKeyHandle::SmartContractState(old_key.clone());
    let old_budget = hot_budget_bytes(
        old_handle.encode_key().expect("old key encodes").len(),
        MeasuredBytes::measured_bytes(&old_value),
    );
    world.smart_contract_state.insert(old_key, old_value);
    backend
        .record_world_snapshot(&world)
        .expect("initial snapshot");

    let (new_key, new_value) = dummy_state_entry(2);
    let new_handle = TieredKeyHandle::SmartContractState(new_key.clone());
    let new_budget = hot_budget_bytes(
        new_handle.encode_key().expect("new key encodes").len(),
        MeasuredBytes::measured_bytes(&new_value),
    );
    backend.reconfigure(true, 1, new_budget, 0, Some(root), None, 0, 0);
    world
        .smart_contract_state
        .insert(new_key, new_value.clone());
    let mut payload = TieredSnapshotPayload::default();
    payload.push_value(new_handle, Some(new_value));
    backend
        .record_world_snapshot_with_payload(&payload)
        .expect("payload snapshot");

    let manifest = backend.last_manifest().expect("manifest recorded");
    let hot_budget = manifest.hot_entries.iter().fold(0_u64, |total, entry| {
        total.saturating_add(entry.hot_budget_bytes())
    });
    assert_eq!(manifest.hot_entries.len(), 2);
    assert!(manifest.cold_entries.is_empty());
    assert_eq!(manifest.hot_budget_overflow_keys, 1);
    assert_eq!(manifest.hot_budget_overflow_bytes, old_budget);
    assert_eq!(hot_budget, old_budget.saturating_add(new_budget));
}
#[test]
fn snapshot_failure_leaves_existing_snapshot_intact() {
    let temp = tempdir().expect("tmpdir");
    let root = temp.path().to_path_buf();
    let mut backend = TieredStateBackend::new(true, 0, 0, 0, Some(root.clone()), None, 0, 0);
    let existing_dir = root.join(format!("{:020}", 1_u64));
    fs::create_dir_all(&existing_dir).expect("create existing snapshot");
    let marker = existing_dir.join("marker.txt");
    fs::write(&marker, b"keep me").expect("write marker");
    let plan = TieredSnapshotPlan {
        root: root.clone(),
        snapshot_dir: existing_dir.clone(),
        manifest: TieredSnapshotManifest {
            snapshot_index: 1,
            total_entries: 0,
            hot_entries: Vec::new(),
            cold_entries: Vec::new(),
            cold_bytes_total: 0,
            cold_reused_entries: 0,
            cold_reused_bytes: 0,
            hot_promotions: 0,
            hot_demotions: 0,
            hot_budget_overflow_keys: 0,
            hot_budget_overflow_bytes: 0,
        },
        cold_entries: Vec::new(),
    };
    let staging_path = plan.snapshot_dir.with_extension("staging");
    fs::write(&staging_path, b"block staging dir creation").expect("write staging file");
    let result = backend.execute_snapshot_plan(plan, &World::default());
    assert!(
        result.is_err(),
        "expected staging collision to fail snapshot"
    );
    assert!(
        marker.exists(),
        "existing snapshot directory should remain when staging fails"
    );
}
