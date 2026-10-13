//! Storage overlays over a genuinely configured recorder policy. Synthetic gateway coordinates
//! exercise row integrity only; they do not establish signed execution or finality evidence.

use std::{collections::BTreeSet, ops::Deref};

use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    block::BlockHeader,
    isi::{Grant, sorafs::SetSorafsReputationJournalAuthorityPolicy},
    permission::Permission,
    sorafs::{
        capacity::{CapacityDeclarationRecord, ProviderId},
        reputation::{
            ReputationJournalAuthorityPolicyV1, StreamTokenRequestRouteV1,
            StreamTokenValidationRequestContextV1, StreamTokenValidationStatusV1,
            derive_stream_token_gateway_id_v1,
            stream_token_delivery::{
                StreamTokenReputationCancellationReasonV1, StreamTokenReputationDeliveryTemplateV1,
            },
        },
        stream_token_gateway::{
            StreamTokenGatewayAdmissionQualificationV1,
            StreamTokenGatewayAdmissionRecordV1 as Record,
            StreamTokenGatewayAdmissionRequestV1 as Request, StreamTokenGatewayQuotaRequestV1,
        },
    },
    transaction::FeePaymentIntent,
};

use super::*;
use crate::{
    query::stream_token_gateway::transition::{self, TransitionInputs},
    smartcontracts::isi::sorafs_reputation::stream_token_delivery::{
        self as delivery, DeliveryState,
    },
    state::{State, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

use iroha_executor_data_model::permission::sorafs::{
    CanManageSorafsReputationJournalPolicy, CanRecordSorafsReputationJournal,
};

const NOW: u64 = 1_000_000;

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

struct StorageState(CertifiedTestChain);
impl Deref for StorageState {
    type Target = State;
    fn deref(&self) -> &State {
        self.0.state().as_ref()
    }
}
fn state() -> StorageState {
    let mut world = World::with(
        [],
        (1..=4).map(|seed| Account::new(account(seed)).build(&account(1))),
        [],
    );
    let provider = ProviderId::new([0x41; 32]);
    world.provider_owners.insert(provider, account(4));
    world.capacity_declarations.insert(
        provider,
        CapacityDeclarationRecord::new(
            provider,
            vec![1],
            1,
            1,
            1,
            2,
            iroha_model_base::metadata::Metadata::default(),
        ),
    );
    let mut config = TestChainConfig::new(world, NOW - 1_000);
    config.genesis_instructions.extend([
        Grant::account_permission(
            Permission::from(CanManageSorafsReputationJournalPolicy),
            account(1),
        )
        .into(),
        Grant::account_permission(
            Permission::from(CanRecordSorafsReputationJournal),
            account(4),
        )
        .into(),
    ]);
    let mut chain = CertifiedTestChain::start(config)
        .map_err(|error| error.error)
        .unwrap();
    let gateway = policy(*chain.state().network_id_ref())
        .qualification
        .gateway_id;
    let recorder = ReputationJournalAuthorityPolicyV1 {
        version: 1,
        revision: 1,
        predecessor_policy_digest: None,
        por_recorder_authority: account(1),
        dispute_recorder_authority: account(1),
        token_recorder_authority: account(4),
        stream_token_delivery: StreamTokenReputationDeliveryTemplateV1 {
            allowed_gateways: vec![gateway],
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            time_to_live_ms: 600_000,
            height_ttl: 1_024,
        },
        max_source_age_ms: 3_600_000,
    };
    let signed = chain.sign(
        &KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519),
        [SetSorafsReputationJournalAuthorityPolicy::new(recorder).into()],
        NOW - 501,
    );
    assert_eq!(chain.commit_at(NOW - 500, vec![signed]), [true]);
    StorageState(chain)
}

fn policy(network_id: NetworkId) -> Policy {
    let mut value = Policy {
        network_id,
        compliance_gateway_id: "storage.test".into(),
        qualification: StreamTokenGatewayAdmissionQualificationV1 {
            gateway_id: derive_stream_token_gateway_id_v1(&network_id, "storage.test").unwrap(),
            revision: 1,
            policy_digest: [0; 32],
            max_pending: 64,
            max_tracked_tokens: 64,
            lease_ttl_ms: 120_000,
        },
        operators: BTreeSet::from([account(1)]),
        observers: BTreeSet::from([account(2)]),
        valid_from_unix_ms: 1,
        valid_until_unix_ms: NOW + 1_000_000,
        max_observation_age_ms: 300_000,
        admission_enabled: true,
    };
    value.qualification.policy_digest = value.calculate_policy_digest().unwrap();
    value
}

fn execution(ordinal: u32) -> Execution {
    Execution {
        height: 3,
        transaction_hash: *Hash::new(ordinal.to_be_bytes()).as_ref(),
        entry_index: ordinal,
        instruction_index: 0,
        recorded_at_unix_ms: NOW,
        authority: account(1),
    }
}

fn header() -> BlockHeader {
    BlockHeader::new(3_u64.try_into().unwrap(), None, None, NOW, 0)
}

fn current(tx: &StateTransaction<'_, '_>, policy: &Policy) -> GatewayCurrentV1 {
    read_current(
        tx.world(),
        &policy.network_id,
        policy.qualification.gateway_id,
    )
    .unwrap()
    .unwrap()
}

fn initialise(tx: &mut StateTransaction<'_, '_>, policy: &Policy) -> GatewayCurrentV1 {
    configure(tx, policy, 0, [0; 32], &execution(0), [0x10; 32]).unwrap();
    current(tx, policy)
}

fn request(nonce: &str) -> Request {
    Request {
        serving_attempt_id: *Hash::new(nonce.as_bytes()).as_ref(),
        context: StreamTokenValidationRequestContextV1::try_new(
            ProviderId::new([0x41; 32]),
            [0x42; 32],
            sorafs_manifest::canonical_manifest_root_cid([0x43; 32]),
            "sorafs.sf1@1.0.0".into(),
            nonce,
            Some(b"Q2Fub25pY2FsVG9rZW4="),
            StreamTokenRequestRouteV1::car_range(64, 1_023).unwrap(),
        )
        .unwrap(),
        token_body_digest: Some([0x44; 32]),
        token_key_version: Some(3),
        validated_at_unix_ms: NOW,
        status: StreamTokenValidationStatusV1::Accepted,
        quota: Some(StreamTokenGatewayQuotaRequestV1 {
            token_id: "11".repeat(16),
            max_streams: 4,
            requests_per_minute: 120,
            rate_limit_bytes: 1_048_576,
            requested_bytes: 960,
            expires_at_epoch: (NOW + 600_000) / 1_000,
            observed_at_epoch: NOW / 1_000,
        }),
    }
}

fn prepare(
    tx: &StateTransaction<'_, '_>,
    policy: &Policy,
    request: &Request,
    execution: &Execution,
) -> (GatewayCurrentV1, TransitionDelta) {
    let current = current(tx, policy);
    let rows = WorldGatewayRows::new(
        tx.world(),
        &policy.network_id,
        policy.qualification.gateway_id,
    )
    .unwrap();
    let delta = transition::admit(
        TransitionInputs {
            policy: &current.policy.policy,
            head: current.head.head,
            execution,
        },
        &rows,
        request,
    )
    .unwrap();
    (current, delta)
}

fn admit(tx: &mut StateTransaction<'_, '_>, policy: &Policy, ordinal: u32, nonce: &str) -> Record {
    let execution = execution(ordinal);
    let (current, delta) = prepare(tx, policy, &request(nonce), &execution);
    let source = delivery::prepare_admission(tx, &delta).unwrap();
    let gateway = prepare_delta(tx, &current, &execution, [0x20; 32], &delta).unwrap();
    gateway.publish(tx);
    source.publish(tx);
    let TransitionResult::Admission(result) = delta.result else {
        panic!("admission");
    };
    result.record
}

// A governed cancellation exercises terminal storage without inventing a successful journal
// append. The certified handler/observation suites cover Delivered and Serving provenance.
fn cancel_delivery(
    tx: &mut StateTransaction<'_, '_>,
    policy: &Policy,
    record: &Record,
    execution: &Execution,
) -> DeliveryState {
    let (source, _) = delivery::read(tx.world(), &policy.network_id, record).unwrap();
    let mut cancellation = execution.clone();
    cancellation.authority = account(1);
    delivery::prepare_cancellation(
        tx,
        &account(1),
        record,
        source.recorder_policy.policy_digest,
        StreamTokenReputationCancellationReasonV1::CredentialUnavailable,
        &cancellation,
        policy.qualification,
    )
    .unwrap()
    .publish(tx);
    delivery::read(tx.world(), &policy.network_id, record)
        .unwrap()
        .1
}

fn snapshot(world: &impl WorldReadOnly) -> Vec<(StatePath, Vec<u8>)> {
    world
        .smart_contract_state()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[test]
fn gateway_storage_policy_initialisation_roundtrip_and_exact_retry() {
    let state = state();
    let policy = policy(state.network_id);
    let gateway = policy.qualification.gateway_id;
    let mut block = state.block(header());
    let mut tx = block.transaction();
    assert_eq!(
        read_current(tx.world(), &policy.network_id, gateway).unwrap(),
        None
    );
    let initial = initialise(&mut tx, &policy);
    assert_eq!(initial.head, GatewayStoredHeadV1::default());
    assert_ne!(
        initial.policy_head.policy_digest,
        initial.policy_head.record_digest
    );
    assert_eq!(
        decode::<GatewayPolicyRecordV1>(&encode(&initial.policy).unwrap()).unwrap(),
        initial.policy
    );
    assert_eq!(
        decode::<GatewayPolicyHeadV1>(&encode(&initial.policy_head).unwrap()).unwrap(),
        initial.policy_head
    );
    assert_eq!(
        decode::<GatewayStoredHeadV1>(&encode(&initial.head).unwrap()).unwrap(),
        initial.head
    );
    let before = snapshot(tx.world());
    configure(&mut tx, &policy, 0, [0; 32], &execution(1), [0x10; 32]).unwrap();
    assert_eq!(
        snapshot(tx.world()),
        before,
        "exact retry cannot append or reset state"
    );
    assert_eq!(
        configure(&mut tx, &policy, 0, [0; 32], &execution(1), [0x11; 32]),
        Err(Error::Conflict)
    );
    assert_eq!(snapshot(tx.world()), before);
}

#[test]
fn gateway_storage_admission_ack_and_release_commit_real_overlay_rows() {
    let state = state();
    let policy = policy(state.network_id);
    let gateway = policy.qualification.gateway_id;
    let mut block = state.block(header());
    let mut tx = block.transaction();
    initialise(&mut tx, &policy);
    let record = admit(&mut tx, &policy, 1, "first");
    let first = current(&tx, &policy);
    assert_eq!(
        (
            first.head.head.revision,
            first.head.head.high_water_sequence,
            first.head.head.live_tokens
        ),
        (1, 1, 1)
    );
    let first_mutation = read_mutation(tx.world(), &policy.network_id, gateway, 1).unwrap();
    assert_eq!(first_mutation.after, first.head.head);
    assert!(first_mutation.write_count > 0);
    assert_eq!(
        decode::<GatewayMutationRecordV1>(&encode(&first_mutation).unwrap()).unwrap(),
        first_mutation
    );
    for key in [
        GatewayRowKey::Admission(1),
        GatewayRowKey::Lease(record.lease_id.unwrap()),
    ] {
        let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
        assert!(rows.read(&key).unwrap().is_some());
    }
    let execution = execution(2);
    let reputation_delivery = cancel_delivery(&mut tx, &policy, &record, &execution);
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    let delta = transition::acknowledge(
        TransitionInputs {
            policy: &policy,
            head: first.head.head,
            execution: &execution,
        },
        &rows,
        &record,
        reputation_delivery,
    )
    .unwrap();
    assert_eq!(
        delta.writes.len(),
        1,
        "the first acknowledgement retains exact permanent provenance"
    );
    assert_eq!(delta.writes[0].key, GatewayRowKey::Acknowledgement(1));
    apply_delta(&mut tx, &first, &execution, [0x21; 32], &delta).unwrap();
    let acked = current(&tx, &policy);
    let ack_mutation = read_mutation(tx.world(), &policy.network_id, gateway, 2).unwrap();
    assert_eq!(ack_mutation.write_count, 1);
    assert_eq!(ack_mutation.predecessor_digest, first.head.mutation_digest);
    assert_eq!(acked.head.head.acknowledged_through_sequence, 1);
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    let Some(GatewayRow::Acknowledgement(original_ack)) =
        rows.read(&GatewayRowKey::Acknowledgement(1)).unwrap()
    else {
        panic!("retained acknowledgement");
    };
    assert_eq!(original_ack.record, record);
    assert_eq!(original_ack.execution, execution);
    assert_eq!(original_ack.policy_revision, policy.qualification.revision);
    assert_eq!(
        decode::<AcknowledgementRowV1>(&encode(&original_ack).unwrap()).unwrap(),
        original_ack
    );
    let execution = self::execution(3);
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    let delta = transition::release_lease(
        TransitionInputs {
            policy: &policy,
            head: acked.head.head,
            execution: &execution,
        },
        &rows,
        &record,
    )
    .unwrap();
    apply_delta(&mut tx, &acked, &execution, [0x22; 32], &delta).unwrap();
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    assert!(
        rows.read(&GatewayRowKey::Lease(record.lease_id.unwrap()))
            .unwrap()
            .is_some()
    );
    assert!(
        rows.read(&GatewayRowKey::LeaseTerminal(record.lease_id.unwrap()))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        rows.read(&GatewayRowKey::Expiry(GatewayExpiryKeyV1 {
            at_unix_ms: record.lease_expires_at_unix_ms.unwrap(),
            target: GatewayExpiryTargetV1::Lease(record.lease_id.unwrap())
        }))
        .unwrap(),
        None
    );
}

#[test]
fn gateway_storage_stale_and_late_invalid_cas_never_publish_partial_rows() {
    let state = state();
    let policy = policy(state.network_id);
    let mut block = state.block(header());
    let mut tx = block.transaction();
    initialise(&mut tx, &policy);
    let (initial, delta) = prepare(&tx, &policy, &request("first"), &execution(1));
    let baseline = snapshot(tx.world());
    let mut invalid = delta.clone();
    invalid.writes.last_mut().unwrap().after = Some(GatewayRow::Context(ContextRowV1 {
        sequence: 1,
        request_digest: [1; 32],
    }));
    assert_eq!(
        apply_delta(&mut tx, &initial, &execution(1), [0x20; 32], &invalid),
        Err(Error::CorruptHistory)
    );
    assert_eq!(snapshot(tx.world()), baseline);
    let mut invalid = delta.clone();
    invalid.writes.swap(0, 1);
    assert_eq!(
        apply_delta(&mut tx, &initial, &execution(1), [0x20; 32], &invalid),
        Err(Error::Invalid)
    );
    assert_eq!(snapshot(tx.world()), baseline);
    let source = delivery::prepare_admission(&tx, &delta).unwrap();
    let gateway = prepare_delta(&tx, &initial, &execution(1), [0x20; 32], &delta).unwrap();
    gateway.publish(&mut tx);
    source.publish(&mut tx);
    let changed = snapshot(tx.world());
    assert_eq!(
        apply_delta(&mut tx, &initial, &execution(2), [0x20; 32], &delta),
        Err(Error::Conflict)
    );
    assert_eq!(snapshot(tx.world()), changed);
    let (current, replay) = prepare(&tx, &policy, &request("first"), &execution(2));
    assert_eq!(replay.before, replay.after);
    apply_delta(&mut tx, &current, &execution(2), [0x20; 32], &replay).unwrap();
    assert_eq!(
        snapshot(tx.world()),
        changed,
        "exact replay cannot allocate a revision"
    );
    let (current, next) = prepare(&tx, &policy, &request("second"), &execution(3));
    let quota_write = next
        .writes
        .iter()
        .find(|write| matches!(write.key, GatewayRowKey::Quota(_)))
        .unwrap();
    let Some(GatewayRow::Quota(mut substituted)) = quota_write.before.clone() else {
        panic!("existing quota");
    };
    substituted.requests_used += 1;
    tx.world.smart_contract_state.insert(
        row_path(policy.qualification.gateway_id, &quota_write.key).unwrap(),
        encode(&substituted).unwrap(),
    );
    let changed = snapshot(tx.world());
    assert_eq!(
        apply_delta(&mut tx, &current, &execution(3), [0x20; 32], &next),
        Err(Error::Conflict)
    );
    assert_eq!(
        snapshot(tx.world()),
        changed,
        "late row CAS cannot publish earlier admission writes"
    );
}

#[test]
fn gateway_storage_immutable_history_and_lifecycle_cannot_be_removed() {
    let state = state();
    let policy = policy(state.network_id);
    let gateway = policy.qualification.gateway_id;
    let mut block = state.block(header());
    let mut tx = block.transaction();
    initialise(&mut tx, &policy);
    let record = admit(&mut tx, &policy, 1, "first");
    let current = current(&tx, &policy);
    let execution = execution(2);
    let reputation_delivery = cancel_delivery(&mut tx, &policy, &record, &execution);
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    let original = rows.read(&GatewayRowKey::Admission(1)).unwrap().unwrap();
    let delta = transition::acknowledge(
        TransitionInputs {
            policy: &policy,
            head: current.head.head,
            execution: &execution,
        },
        &rows,
        &record,
        reputation_delivery,
    )
    .unwrap();
    let Some(GatewayRow::Lease(lease)) = rows
        .read(&GatewayRowKey::Lease(record.lease_id.unwrap()))
        .unwrap()
    else {
        panic!("lease");
    };
    let lifecycle_key = GatewayRowKey::QuotaLifecycle(lease.token_scope);
    let lifecycle = rows.read(&lifecycle_key).unwrap().unwrap();
    let baseline = snapshot(tx.world());
    for (key, before) in [
        (GatewayRowKey::Admission(1), original),
        (lifecycle_key, lifecycle),
    ] {
        let mut invalid = delta.clone();
        invalid.writes.push(GatewayRowWrite {
            key,
            before: Some(before),
            after: None,
        });
        assert_eq!(
            apply_delta(&mut tx, &current, &execution, [0x21; 32], &invalid),
            Err(Error::Invalid)
        );
        assert_eq!(snapshot(tx.world()), baseline);
    }
}

#[test]
fn gateway_storage_rotation_preserves_original_policy_and_live_obligations() {
    let state = state();
    let policy = policy(state.network_id);
    let gateway = policy.qualification.gateway_id;
    let mut block = state.block(header());
    let mut tx = block.transaction();
    initialise(&mut tx, &policy);
    let record = admit(&mut tx, &policy, 1, "first");
    let original = current(&tx, &policy);
    let mut replacement = policy.clone();
    replacement.qualification.revision = 2;
    replacement.qualification.max_pending = 1;
    replacement.qualification.max_tracked_tokens = 1;
    replacement.qualification.lease_ttl_ms = 1_000;
    replacement.operators = BTreeSet::from([account(3)]);
    replacement.admission_enabled = false;
    replacement.qualification.policy_digest = replacement.calculate_policy_digest().unwrap();
    configure(
        &mut tx,
        &replacement,
        1,
        policy.qualification.policy_digest,
        &execution(2),
        [0x30; 32],
    )
    .unwrap();
    let rotated = current(&tx, &replacement);
    assert_eq!(rotated.head, original.head);
    assert_eq!(
        rotated.policy.predecessor_digest,
        original.policy_head.record_digest
    );
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    let Some(GatewayRow::Admission(admission)) = rows.read(&GatewayRowKey::Admission(1)).unwrap()
    else {
        panic!("retained original admission")
    };
    assert_eq!(admission.record, record);
    let mut execution = execution(3);
    execution.authority = account(3);
    let reputation_delivery = cancel_delivery(&mut tx, &replacement, &record, &execution);
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    let delta = transition::acknowledge(
        TransitionInputs {
            policy: &replacement,
            head: rotated.head.head,
            execution: &execution,
        },
        &rows,
        &record,
        reputation_delivery,
    )
    .unwrap();
    apply_delta(&mut tx, &rotated, &execution, [0x31; 32], &delta).unwrap();
    assert_eq!(
        current(&tx, &replacement)
            .head
            .head
            .acknowledged_through_sequence,
        1
    );
    // Retaining a valid older policy does not authorize executing under it after replacement.
    let mut substituted = admission;
    substituted.execution.entry_index = 4;
    tx.world.smart_contract_state.insert(
        row_path(gateway, &GatewayRowKey::Admission(1)).unwrap(),
        encode(&substituted).unwrap(),
    );
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    assert_eq!(
        rows.read(&GatewayRowKey::Admission(1)),
        Err(Error::CorruptHistory)
    );
}

#[test]
fn gateway_storage_missing_or_rolled_back_heads_cannot_hide_retained_history() {
    let state = state();
    let policy = policy(state.network_id);
    let gateway = policy.qualification.gateway_id;
    let mut block = state.block(header());
    let mut tx = block.transaction();
    let initial = initialise(&mut tx, &policy);
    admit(&mut tx, &policy, 1, "first");
    let live = current(&tx, &policy);
    tx.world
        .smart_contract_state
        .insert(head_path(gateway).unwrap(), encode(&initial.head).unwrap());
    assert_eq!(
        read_current(tx.world(), &policy.network_id, gateway),
        Err(Error::CorruptHistory)
    );
    tx.world
        .smart_contract_state
        .remove(head_path(gateway).unwrap());
    assert_eq!(
        read_current(tx.world(), &policy.network_id, gateway),
        Err(Error::CorruptHistory)
    );
    tx.world
        .smart_contract_state
        .insert(head_path(gateway).unwrap(), encode(&live.head).unwrap());
    let mut replacement = policy.clone();
    replacement.qualification.revision = 2;
    replacement.admission_enabled = false;
    replacement.qualification.policy_digest = replacement.calculate_policy_digest().unwrap();
    configure(
        &mut tx,
        &replacement,
        1,
        policy.qualification.policy_digest,
        &execution(2),
        [0x30; 32],
    )
    .unwrap();
    tx.world.smart_contract_state.insert(
        policy_head_path(gateway).unwrap(),
        encode(&initial.policy_head).unwrap(),
    );
    assert_eq!(
        read_current(tx.world(), &policy.network_id, gateway),
        Err(Error::CorruptHistory)
    );
    tx.world
        .smart_contract_state
        .remove(policy_head_path(gateway).unwrap());
    assert_eq!(
        read_current(tx.world(), &policy.network_id, gateway),
        Err(Error::CorruptHistory)
    );
}

#[test]
fn gateway_storage_expiry_prefix_is_exact_ordered_bounded_and_gateway_scoped() {
    let state = state();
    let network = state.network_id;
    let policy = policy(network);
    let gateway = policy.qualification.gateway_id;
    let mut block = state.block(header());
    let mut tx = block.transaction();
    initialise(&mut tx, &policy);
    admit(&mut tx, &policy, 1, "first");
    let world = &mut *tx.world;
    let keys = [
        GatewayExpiryKeyV1 {
            at_unix_ms: 9,
            target: GatewayExpiryTargetV1::Lease([3; 32]),
        },
        GatewayExpiryKeyV1 {
            at_unix_ms: 10,
            target: GatewayExpiryTargetV1::Lease([2; 32]),
        },
        GatewayExpiryKeyV1 {
            at_unix_ms: 10,
            target: GatewayExpiryTargetV1::Quota([1; 32]),
        },
        GatewayExpiryKeyV1 {
            at_unix_ms: 100,
            target: GatewayExpiryTargetV1::Lease([1; 32]),
        },
    ];
    for key in keys.into_iter().rev() {
        world.smart_contract_state.insert(
            row_path(gateway, &GatewayRowKey::Expiry(key)).unwrap(),
            encode(&key).unwrap(),
        );
    }
    world.smart_contract_state.insert(
        row_path([0x52; 32], &GatewayRowKey::Expiry(keys[0])).unwrap(),
        encode(&keys[0]).unwrap(),
    );
    {
        let rows = WorldGatewayRows::new(world, &network, gateway).unwrap();
        assert_eq!(rows.expiry_prefix(8, 257).unwrap(), vec![]);
        assert_eq!(rows.expiry_prefix(10, 2).unwrap(), keys[..2]);
        assert_eq!(rows.expiry_prefix(10, 257).unwrap(), keys[..3]);
        assert_eq!(rows.expiry_prefix(100, 257).unwrap(), keys);
        assert_eq!(rows.expiry_prefix(100, 0), Err(Error::Invalid));
        assert_eq!(rows.expiry_prefix(100, 258), Err(Error::Invalid));
    }
    world.smart_contract_state.insert(
        row_path(gateway, &GatewayRowKey::Expiry(keys[0])).unwrap(),
        encode(&keys[1]).unwrap(),
    );
    let rows = WorldGatewayRows::new(world, &network, gateway).unwrap();
    assert_eq!(rows.expiry_prefix(100, 257), Err(Error::CorruptHistory));
}

#[test]
fn gateway_storage_orphans_foreign_network_and_execution_mismatch_fail_atomically() {
    let state = state();
    let policy = policy(state.network_id);
    let gateway = policy.qualification.gateway_id;
    let mut block = state.block(header());
    let mut tx = block.transaction();
    let pristine = snapshot(tx.world());
    let orphan = path(gateway, "unrecognised/orphan").unwrap();
    tx.world
        .smart_contract_state
        .insert(orphan.clone(), vec![1]);
    let before = snapshot(tx.world());
    assert_eq!(
        configure(&mut tx, &policy, 0, [0; 32], &execution(0), [0x10; 32]),
        Err(Error::CorruptHistory)
    );
    assert_eq!(snapshot(tx.world()), before);
    tx.world.smart_contract_state.remove(orphan);
    let mut wrong_time = execution(0);
    wrong_time.recorded_at_unix_ms += 1;
    assert_eq!(
        configure(&mut tx, &policy, 0, [0; 32], &wrong_time, [0x10; 32]),
        Err(Error::BindingMismatch)
    );
    assert_eq!(snapshot(tx.world()), pristine);
    initialise(&mut tx, &policy);
    let foreign = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new(b"foreign storage network"),
    ));
    assert_eq!(
        read_current(tx.world(), &foreign, gateway),
        Err(Error::CorruptHistory)
    );
}

#[test]
fn gateway_storage_bounded_canonical_rows_reject_oversize_and_wrong_types() {
    assert_eq!(encode(&vec![0_u8; MAX_ROW_BYTES]), Err(Error::Invalid));
    assert_eq!(
        decode::<GatewayStoredHeadV1>(&vec![0; MAX_ROW_BYTES + 1]),
        Err(Error::CorruptHistory)
    );
    assert_eq!(
        decode::<GatewayStoredHeadV1>(&[]),
        Err(Error::CorruptHistory)
    );
    let key = GatewayExpiryKeyV1 {
        at_unix_ms: 10,
        target: GatewayExpiryTargetV1::Lease([1; 32]),
    };
    assert_eq!(
        encode_row(&GatewayRowKey::Context([1; 32]), &GatewayRow::Expiry(key)),
        Err(Error::CorruptHistory)
    );
    let mut bytes = encode(&GatewayStoredHeadV1::default()).unwrap();
    bytes.push(0);
    assert_eq!(
        decode::<GatewayStoredHeadV1>(&bytes),
        Err(Error::CorruptHistory)
    );
}

#[test]
fn gateway_storage_acknowledgement_is_atomic_immutable_and_policy_authenticated() {
    let state = state();
    let policy = policy(state.network_id);
    let gateway = policy.qualification.gateway_id;
    let mut block = state.block(header());
    let mut tx = block.transaction();
    initialise(&mut tx, &policy);
    let record = admit(&mut tx, &policy, 1, "indexed-ack");
    let before = current(&tx, &policy);
    let execution = execution(2);
    let reputation_delivery = cancel_delivery(&mut tx, &policy, &record, &execution);
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    let delta = transition::acknowledge(
        TransitionInputs {
            policy: &policy,
            head: before.head.head,
            execution: &execution,
        },
        &rows,
        &record,
        reputation_delivery,
    )
    .unwrap();
    let snapshot_before = snapshot(tx.world());
    let mut missing = delta.clone();
    missing.writes.clear();
    assert_eq!(
        apply_delta(&mut tx, &before, &execution, [0x81; 32], &missing),
        Err(Error::Invalid)
    );
    assert_eq!(snapshot(tx.world()), snapshot_before);
    apply_delta(&mut tx, &before, &execution, [0x82; 32], &delta).unwrap();
    let after = current(&tx, &policy);
    let key = GatewayRowKey::Acknowledgement(1);
    let path = row_path(gateway, &key).unwrap();
    let bytes = tx
        .world()
        .smart_contract_state()
        .get(&path)
        .unwrap()
        .clone();
    let original: AcknowledgementRowV1 = decode(&bytes).unwrap();
    assert_eq!(original.execution, execution);
    let replay_execution = self::execution(3);
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    let replay = transition::acknowledge(
        TransitionInputs {
            policy: &policy,
            head: after.head.head,
            execution: &replay_execution,
        },
        &rows,
        &record,
        original.reputation_delivery.clone(),
    )
    .unwrap();
    assert!(replay.writes.is_empty());
    assert_eq!(replay.before, replay.after);
    apply_delta(&mut tx, &after, &replay_execution, [0x83; 32], &replay).unwrap();
    assert_eq!(tx.world().smart_contract_state().get(&path), Some(&bytes));
    tx.world.smart_contract_state.remove(path.clone());
    assert!(matches!(
        read_current(tx.world(), &policy.network_id, gateway),
        Err(Error::CorruptHistory)
    ));
    let mut forged = original.clone();
    forged.policy_revision = 2;
    tx.world
        .smart_contract_state
        .insert(path.clone(), encode(&forged).unwrap());
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    assert!(
        rows.read(&key).is_err(),
        "uncommitted acknowledgement policy cannot be invented"
    );
    tx.world.smart_contract_state.insert(path, bytes);
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway).unwrap();
    assert_eq!(
        rows.read(&key).unwrap(),
        Some(GatewayRow::Acknowledgement(original))
    );
}
