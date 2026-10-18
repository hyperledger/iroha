//! Integration tests covering the `SoraFS` pin registry flows.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey, PublicKey, Signature};
use iroha_data_model::{
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{
            ApprovePinManifest, BindManifestAlias, CompleteReplicationOrder, IssueReplicationOrder,
            RegisterPinManifest, RetirePinManifest, SetProviderIngestCompletionAuthority,
        },
    },
    prelude::*,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ChunkerProfileHandle, ManifestAliasBinding, ManifestAliasId, ManifestAliasRecord,
            ManifestDigest, ManifestRootCid, PinManifestRecord, PinPolicy, PinStatus,
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
            ProviderIngestFinalizedAnchorV1, ReplicationOrderId, ReplicationOrderRecord,
            ReplicationOrderStatus, StorageClass,
        },
    },
};
use iroha_executor_data_model::permission::sorafs::{
    CanBindSorafsAlias, CanCompleteSorafsReplicationOrder, CanIssueSorafsReplicationOrder,
};
use iroha_model_base::domain::DomainId;
use mv::storage::StorageReadOnly;
use norito::{decode_from_bytes, json, json::Value, to_bytes};
use sorafs_manifest::{
    AliasBindingV1, CouncilSignature, DagCodecId, GovernanceProofs, ManifestBuilder, ManifestV1,
    REPLICATION_ORDER_VERSION_V1, ReplicationAssignmentV1, ReplicationOrderSlaV1,
    ReplicationOrderV1, chunker_registry,
    pin_registry::{AliasProofBundleV1, alias_merkle_root, alias_proof_signature_digest},
};
use std::{collections::BTreeSet, convert::TryInto, env, fs, num::NonZeroU64, path::PathBuf};
const FIXTURE_PATH: &str = "tests/fixtures/sorafs_pin_registry/snapshot.json";
const ORDER_ISSUED_EPOCH: u64 = 20;
const ORDER_DEADLINE_EPOCH: u64 = 28;
#[test]
fn pin_registry_snapshot_matches_fixture() {
    let mut state = make_state();
    seed_completion_anchor(&state);
    assert_eq!(
        state
            .view()
            .block_hashes()
            .first()
            .map(|hash| *hash.as_ref()),
        Some(completion_anchor().block_hash),
        "provider completion anchor must name the exact committed prefix"
    );
    let digest = default_digest();
    let chunk_digest = default_chunk_digest();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let alias_binding = alias_binding_for(digest, "sora", "docs", 12, 36, &council_keys);
    {
        // Approval and completion observe their real consensus-time headers in
        // separate component overlays; neither overlay invents block finality.
        let mut block = state.block(block_header_at(2, 5_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
        bootstrap_sorafs(&mut tx);
        register_and_approve(&mut tx, digest, chunk_digest, &council_keys);
        assert_eq!(
            tx.world()
                .pin_manifests()
                .get(&digest)
                .expect("approved pin")
                .approved_epoch,
            Some(5)
        );
        BindManifestAlias {
            digest,
            binding: alias_binding.clone(),
            bound_epoch: 12,
            expiry_epoch: 36,
        }
        .execute(&alice(), &mut tx)
        .expect("bind alias");
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit the component approval overlay");
    }
    let mut block = state.block(block_header_at(2, 25_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    let providers = [
        ProviderId::new([0x51; 32]),
        ProviderId::new([0x52; 32]),
        ProviderId::new([0x53; 32]),
    ];
    let order_id = ReplicationOrderId::new([0x44; 32]);
    let order_struct = replication_order(order_id, digest, &providers, 3);
    let order_payload = norito::to_bytes(&order_struct).expect("encode replication order");
    IssueReplicationOrder {
        order_id,
        order_payload,
        issued_epoch: ORDER_ISSUED_EPOCH,
        deadline_epoch: ORDER_DEADLINE_EPOCH,
        musubi_archive: None,
    }
    .execute(&alice(), &mut tx)
    .expect("issue replication order");
    for provider_id in providers {
        CompleteReplicationOrder {
            order_id,
            provider_id,
            completion_epoch: 25,
            expected_authority: completion_authority(&alice()),
            expected_assignment_revision: 1,
            finalized_anchor: completion_anchor(),
        }
        .execute(&alice(), &mut tx)
        .expect("complete provider replication assignment");
    }
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit block");
    let view = state.view();
    let world = view.world();
    let manifest = world.pin_manifests().get(&digest).expect("manifest stored");
    let alias_id = ManifestAliasId::from(&alias_binding);
    let alias_record = world
        .manifest_aliases()
        .get(&alias_id)
        .expect("alias stored");
    let order_record = world
        .replication_orders()
        .get(&order_id)
        .expect("order stored");
    let snapshot = snapshot_json(manifest, alias_record, order_record);
    let fixture = load_fixture();
    if env::var_os("UPDATE_FIXTURES").is_some() {
        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
        let mut payload = norito::json::to_vec_pretty(&snapshot).expect("serialize fixture");
        payload.push(b'\n');
        fs::write(&fixture_path, payload).expect("write fixture");
        panic!(
            "fixture updated: {}. Re-run tests without UPDATE_FIXTURES to verify.",
            fixture_path.display()
        );
    }
    assert_eq!(
        snapshot, fixture,
        "generated snapshot does not match fixture JSON"
    );
}
#[test]
fn alias_proof_fixture_decodes() {
    let fixture = load_fixture();
    let alias_entry = fixture["aliases"]
        .as_array()
        .and_then(|array| array.first())
        .and_then(Value::as_object)
        .expect("alias fixture entry");
    let proof_b64 = alias_entry
        .get("proof_b64")
        .and_then(Value::as_str)
        .expect("alias proof base64");
    let proof_bytes = BASE64_STD
        .decode(proof_b64)
        .expect("alias proof base64 decoding");
    let bundle: AliasProofBundleV1 =
        decode_from_bytes(&proof_bytes).expect("decode alias proof bundle");
    assert_eq!(bundle.binding.alias, "sora/docs");
    assert_eq!(bundle.binding.bound_at, 12);
    assert_eq!(bundle.binding.expiry_epoch, 36);
    assert_eq!(
        bundle.binding.manifest_cid.as_slice(),
        root_cid_for_manifest(default_digest()).as_bytes()
    );
    assert!(
        !bundle.council_signatures.is_empty(),
        "alias proof bundle must contain council signatures"
    );
    let reencoded = to_bytes(&bundle).expect("re-encode alias proof bundle");
    assert_eq!(
        BASE64_STD.encode(reencoded),
        proof_b64,
        "alias proof bundle must roundtrip to the fixture payload"
    );
    let first_sig = &bundle.council_signatures[0];
    let signer =
        PublicKey::from_bytes(Algorithm::Ed25519, &first_sig.signer).expect("parse signer key");
    let signature = Signature::try_from_bytes(&first_sig.signature)
        .expect("council fixture signature must pass checked admission");
    let digest = alias_proof_signature_digest(&bundle);
    signature
        .verify(&signer, digest.as_ref())
        .expect("council signature verifies");
}
#[test]
fn replication_order_fixture_decodes() {
    let fixture = load_fixture();
    let order_entry = fixture["replication_orders"]
        .as_array()
        .and_then(|array| array.first())
        .and_then(Value::as_object)
        .expect("replication order fixture entry");
    let order_b64 = order_entry
        .get("canonical_order_b64")
        .and_then(Value::as_str)
        .expect("replication order base64");
    let order_bytes = BASE64_STD
        .decode(order_b64)
        .expect("replication order base64 decoding");
    let order: ReplicationOrderV1 =
        decode_from_bytes(&order_bytes).expect("decode replication order");
    assert_eq!(order.order_id, [0x44; 32]);
    assert_eq!(order.manifest_digest, *default_digest().as_bytes());
    assert_eq!(order.target_replicas, 3);
    assert_eq!(order.assignments.len(), 3);
    assert_eq!(
        order.chunking_profile,
        format!(
            "{}.{}@{}",
            default_chunker().namespace,
            default_chunker().name,
            default_chunker().semver
        )
    );
    assert_eq!(order.issued_at, ORDER_ISSUED_EPOCH);
    assert_eq!(
        order_entry.get("issued_epoch").and_then(Value::as_u64),
        Some(order.issued_at)
    );
    assert_eq!(order.deadline_at, ORDER_DEADLINE_EPOCH);
    assert_eq!(
        order_entry.get("deadline_epoch").and_then(Value::as_u64),
        Some(order.deadline_at)
    );
    assert_eq!(
        u64::from(order.sla.ingest_deadline_secs),
        order.deadline_at - order.issued_at
    );
    let reencoded = to_bytes(&order).expect("re-encode replication order");
    assert_eq!(
        BASE64_STD.encode(reencoded),
        order_b64,
        "replication order canonical payload must match fixture bytes"
    );
}
#[test]
fn duplicate_alias_binding_is_rejected() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    {
        let mut block = state.block(block_header(1));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
        bootstrap_sorafs(&mut tx);
        let digest = default_digest();
        let chunk_digest = default_chunk_digest();
        register_and_approve(&mut tx, digest, chunk_digest, &council_keys);
        let alias_binding = alias_binding_for(digest, "sora", "docs", 12, 36, &council_keys);
        BindManifestAlias {
            digest,
            binding: alias_binding,
            bound_epoch: 12,
            expiry_epoch: 36,
        }
        .execute(&alice(), &mut tx)
        .expect("initial alias bind succeeds");
        tx.apply();
        block
            .commit_empty_block_for_testing()
            .expect("commit block");
    }
    let digest_b = manifest_digest_for_seed(0xBB);
    let chunk_digest_b = chunk_digest_for_seed(0xBB);
    let mut block = state.block(block_header(2));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    register_and_approve(&mut tx, digest_b, chunk_digest_b, &council_keys);
    let alias_binding = alias_binding_for(digest_b, "sora", "docs", 16, 36, &council_keys);
    let err = BindManifestAlias {
        digest: digest_b,
        binding: alias_binding,
        bound_epoch: 16,
        expiry_epoch: 36,
    }
    .execute(&alice(), &mut tx)
    .expect_err("duplicate alias binding must fail");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => {
            assert!(
                message.contains("alias `sora/docs` is already"),
                "expected duplicate alias error message, got {message}"
            );
        }
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn replication_order_with_mismatched_profile_is_rejected() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let digest = default_digest();
    let chunk_digest = default_chunk_digest();
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    register_and_approve(&mut tx, digest, chunk_digest, &council_keys);
    let providers = [
        ProviderId::new([0x61; 32]),
        ProviderId::new([0x62; 32]),
        ProviderId::new([0x63; 32]),
    ];
    let order_id = ReplicationOrderId::new([0x45; 32]);
    let mut order_struct = replication_order(order_id, digest, &providers, 3);
    order_struct.chunking_profile = "sorafs.chunker@9.9.9".into();
    let order_payload = norito::to_bytes(&order_struct).expect("encode replication order");
    let err = IssueReplicationOrder {
        order_id,
        order_payload,
        issued_epoch: ORDER_ISSUED_EPOCH,
        deadline_epoch: ORDER_DEADLINE_EPOCH,
        musubi_archive: None,
    }
    .execute(&alice(), &mut tx)
    .expect_err("replication order with mismatched profile must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => {
            assert!(
                message.contains("unknown chunker handle"),
                "expected unknown chunker handle validation failure, got {message}"
            );
        }
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn alias_binding_with_expiry_before_bound_is_rejected() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    let digest = default_digest();
    let chunk_digest = default_chunk_digest();
    register_and_approve(&mut tx, digest, chunk_digest, &council_keys);
    let alias_binding = alias_binding_for(digest, "sora", "docs", 12, 10, &council_keys);
    let err = BindManifestAlias {
        digest,
        binding: alias_binding,
        bound_epoch: 12,
        expiry_epoch: 10,
    }
    .execute(&alice(), &mut tx)
    .expect_err("expiry before bound must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => {
            assert!(
                message.contains("expiry epoch"),
                "expected expiry-before-bound rejection, got {message}"
            );
        }
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn alias_binding_exceeding_retention_is_rejected() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    let digest = default_digest();
    let chunk_digest = default_chunk_digest();
    register_and_approve(&mut tx, digest, chunk_digest, &council_keys);
    let expiry_after_retention = default_policy().retention_epoch + 1;
    let alias_binding = alias_binding_for(
        digest,
        "sora",
        "docs",
        12,
        expiry_after_retention,
        &council_keys,
    );
    let err = BindManifestAlias {
        digest,
        binding: alias_binding,
        bound_epoch: 12,
        expiry_epoch: expiry_after_retention,
    }
    .execute(&alice(), &mut tx)
    .expect_err("expiry after retention must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => {
            assert!(
                message.contains("retention"),
                "expected retention guard, got {message}"
            );
        }
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn replication_order_below_min_replicas_is_rejected() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let digest = default_digest();
    let chunk_digest = default_chunk_digest();
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    register_and_approve(&mut tx, digest, chunk_digest, &council_keys);
    let providers = [
        ProviderId::new([0x71; 32]),
        ProviderId::new([0x72; 32]),
        ProviderId::new([0x73; 32]),
    ];
    let order_id = ReplicationOrderId::new([0x46; 32]);
    let order_struct = replication_order(order_id, digest, &providers, 1);
    let order_payload = norito::to_bytes(&order_struct).expect("encode replication order");
    let err = IssueReplicationOrder {
        order_id,
        order_payload,
        issued_epoch: ORDER_ISSUED_EPOCH,
        deadline_epoch: ORDER_DEADLINE_EPOCH,
        musubi_archive: None,
    }
    .execute(&alice(), &mut tx)
    .expect_err("replication order below minimum replicas must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => {
            assert!(
                message.contains("target replicas"),
                "expected target replicas rejection, got {message}"
            );
        }
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn register_manifest_requires_retained_component_invocation() {
    let state = make_state();
    let invocation = Hash::prehashed([0x91; Hash::LENGTH]);
    let instruction = RegisterPinManifest {
        manifest_payload: manifest_payload_for_seed(0xAA),
        alias: None,
        successor_of: None,
    };
    {
        let mut block = state.block(block_header(1));
        let mut tx = block.transaction();
        tx.tx_call_hash = Some(invocation);
        bootstrap_sorafs(&mut tx);
        let alice_before = pin_fee_balance(&tx, &alice());
        let treasury = tx.gov.sorafs_pin_fee_treasury_account.clone();
        let treasury_before = pin_fee_balance(&tx, &treasury);
        let error = instruction
            .clone()
            .execute(&alice(), &mut tx)
            .expect_err("copying a call hash cannot create its retained invocation");
        assert!(
            matches!(error, InstructionExecutionError::InvariantViolation(reason)
            if reason.contains("FASTPQ source has no retained producer invocation"))
        );
        assert!(tx.world().pin_manifests().get(&default_digest()).is_none());
        assert_eq!(pin_fee_balance(&tx, &alice()), alice_before);
        assert_eq!(pin_fee_balance(&tx, &treasury), treasury_before);
    }
    {
        let mut block = state.block(block_header(1));
        // This existing fixture API retains a finite E owner; it does not
        // authenticate a Network input or grant finalized publication authority.
        let mut tx = block.transaction_for_fastpq_testing(invocation);
        bootstrap_sorafs(&mut tx);
        instruction
            .execute(&alice(), &mut tx)
            .expect("the same call hash with its actual retained component owner");
        assert!(tx.world().pin_manifests().get(&default_digest()).is_some());
    }
    assert!(
        state
            .view()
            .world()
            .pin_manifests()
            .get(&default_digest())
            .is_none()
    );
}
#[test]
fn register_manifest_rejects_unknown_chunker_profile() {
    let state = make_state();
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    let mut manifest = manifest_fixture(0xCC);
    manifest.chunking.namespace = "unknown".into();
    manifest.chunking.name = "mystery".into();
    let err = RegisterPinManifest {
        manifest_payload: manifest.encode().expect("encode invalid manifest"),
        alias: None,
        successor_of: None,
    }
    .execute(&alice(), &mut tx)
    .expect_err("manifest with unknown chunker must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert!(
            message.contains("chunker descriptor mismatch"),
            "expected chunker descriptor validation failure, got {message}"
        ),
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn register_manifest_rejects_policy_above_governance_replica_ceiling() {
    let mut state = make_state();
    state.gov.sorafs_pin_policy.max_replicas_ceiling = Some(2);
    assert_governed_policy_rejection(
        &state,
        default_policy(),
        "pin policy exceeds maximum replicas 2",
    );
}
#[test]
fn register_manifest_rejects_policy_beyond_governance_retention_ceiling() {
    let mut state = make_state();
    state.gov.sorafs_pin_policy.max_retention_epoch = Some(30);
    let mut policy = default_policy();
    policy.retention_epoch = 31;
    assert_governed_policy_rejection(&state, policy, "pin retention epoch must be <= 30");
}
#[test]
fn register_manifest_rejects_storage_class_outside_governance_allowlist() {
    let mut state = make_state();
    state.gov.sorafs_pin_policy.allowed_storage_classes =
        Some(BTreeSet::from([StorageClass::Cold]));
    assert_governed_policy_rejection(
        &state,
        default_policy(),
        "storage class `Hot` is not permitted by policy",
    );
}
#[test]
fn register_manifest_rejects_unknown_successor() {
    let state = make_state();
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    let unknown_parent = manifest_digest_for_seed(0xF1);
    let err = RegisterPinManifest {
        manifest_payload: manifest_payload_for_seed(0xE1),
        alias: None,
        successor_of: Some(unknown_parent),
    }
    .execute(&alice(), &mut tx)
    .expect_err("successor must reference existing manifest");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert!(
            message.contains("is not registered"),
            "expected unknown successor message, got {message}"
        ),
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn register_manifest_rejects_self_successor() {
    let state = make_state();
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    let digest = manifest_digest_for_seed(0xE2);
    let err = RegisterPinManifest {
        manifest_payload: manifest_payload_for_seed(0xE2),
        alias: None,
        successor_of: Some(digest),
    }
    .execute(&alice(), &mut tx)
    .expect_err("manifest cannot succeed itself");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert!(
            message.contains("cannot declare itself as successor"),
            "expected self-successor guard message, got {message}"
        ),
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn register_manifest_accepts_active_successor() {
    let state = make_state();
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    let parent = manifest_digest_for_seed(0xE3);
    RegisterPinManifest {
        manifest_payload: manifest_payload_for_seed(0xE3),
        alias: None,
        successor_of: None,
    }
    .execute(&alice(), &mut tx)
    .expect("register predecessor");
    tx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit predecessor");
    let mut block = state.block(block_header(2));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    RegisterPinManifest {
        manifest_payload: manifest_payload_for_seed(0xE4),
        alias: None,
        successor_of: Some(parent),
    }
    .execute(&alice(), &mut tx)
    .expect("active predecessor should accept successor");
    let stored = tx
        .world()
        .pin_manifests()
        .get(&manifest_digest_for_seed(0xE4))
        .expect("successor stored");
    assert_eq!(stored.successor_of, Some(parent));
}
#[test]
fn register_manifest_rejects_retired_successor() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let parent = manifest_digest_for_seed(0xE5);
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    register_and_approve(&mut tx, parent, chunk_digest_for_seed(0xE5), &council_keys);
    tx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit approved predecessor");
    let mut block = state.block(block_header(2));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    RetirePinManifest {
        digest: parent,
        reason: None,
    }
    .execute(&alice(), &mut tx)
    .expect("retire predecessor");
    tx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit retirement");
    let mut block = state.block(block_header(3));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    assert!(matches!(
        tx.world()
            .pin_manifests()
            .get(&parent)
            .expect("retired predecessor")
            .status,
        PinStatus::Retired(_)
    ));
    let err = RegisterPinManifest {
        manifest_payload: manifest_payload_for_seed(0xE6),
        alias: None,
        successor_of: Some(parent),
    }
    .execute(&alice(), &mut tx)
    .expect_err("successor must reject retired predecessor");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert!(
            message.contains("must be approved and live"),
            "expected retired successor guard message, got {message}"
        ),
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn register_manifest_with_successor_persists_pointer() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let parent = manifest_digest_for_seed(0xE7);
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    register_and_approve(&mut tx, parent, chunk_digest_for_seed(0xE7), &council_keys);
    tx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit approved predecessor");
    let mut block = state.block(block_header(2));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    let child = manifest_digest_for_seed(0xE8);
    RegisterPinManifest {
        manifest_payload: manifest_payload_for_seed(0xE8),
        alias: None,
        successor_of: Some(parent),
    }
    .execute(&alice(), &mut tx)
    .expect("register successor manifest");
    let stored = tx
        .world()
        .pin_manifests()
        .get(&child)
        .cloned()
        .expect("successor stored");
    assert_eq!(stored.successor_of.as_ref(), Some(&parent));
}
#[test]
fn bind_alias_rejects_expiry_before_bound_epoch() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let digest = manifest_digest_for_seed(0xD1);
    let chunk_digest = chunk_digest_for_seed(0xD1);
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    register_and_approve(&mut tx, digest, chunk_digest, &council_keys);
    let alias_binding = alias_binding_for(digest, "sora", "docs", 20, 18, &council_keys);
    let err = BindManifestAlias {
        digest,
        binding: alias_binding,
        bound_epoch: 20,
        expiry_epoch: 18,
    }
    .execute(&alice(), &mut tx)
    .expect_err("alias expiry earlier than bound epoch must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert!(
            message.contains("expiry epoch must be greater than or equal to bound epoch"),
            "expected expiry guard message, got {message}"
        ),
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn bind_alias_rejects_bound_epoch_before_approval() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let digest = manifest_digest_for_seed(0xD2);
    let chunk_digest = chunk_digest_for_seed(0xD2);
    let mut block = state.block(block_header_at(1, 5_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    register_and_approve(&mut tx, digest, chunk_digest, &council_keys);
    assert_eq!(
        tx.world()
            .pin_manifests()
            .get(&digest)
            .expect("approved pin")
            .approved_epoch,
        Some(5)
    );
    let alias_binding = alias_binding_for(digest, "sora", "docs", 4, 20, &council_keys);
    let err = BindManifestAlias {
        digest,
        binding: alias_binding,
        bound_epoch: 4,
        expiry_epoch: 20,
    }
    .execute(&alice(), &mut tx)
    .expect_err("alias bound epoch before approval must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert!(
            message.contains("bound_epoch 4 precedes manifest approval epoch 5"),
            "expected approval-bound guard message, got {message}"
        ),
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
#[test]
fn bind_alias_rejects_expiry_after_retention_epoch() {
    let mut state = make_state();
    let council_keys = council_keypair();
    configure_council_approval(&mut state, &council_keys);
    let digest = manifest_digest_for_seed(0xD3);
    let chunk_digest = chunk_digest_for_seed(0xD3);
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    register_and_approve(&mut tx, digest, chunk_digest, &council_keys);
    let alias_binding = alias_binding_for(
        digest,
        "sora",
        "docs",
        12,
        default_policy().retention_epoch + 5,
        &council_keys,
    );
    let err = BindManifestAlias {
        digest,
        binding: alias_binding,
        bound_epoch: 12,
        expiry_epoch: default_policy().retention_epoch + 5,
    }
    .execute(&alice(), &mut tx)
    .expect_err("alias expiry beyond retention must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert!(
            message.contains("expiry epoch"),
            "expected retention guard message, got {message}"
        ),
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
}
fn make_state() -> State {
    let kura = Kura::blank_kura_for_testing();
    let live = LiveQueryStore::start_test();
    let default_domain =
        DomainId::try_new("default", "universal").expect("explicit fixture domain");
    let alice = alice();
    let bob = iroha_test_samples::BOB_ID.clone();
    let domain = Domain::new(default_domain.clone()).build(&alice);
    // The pin fixture starts with its fee-asset owning domain. Live domain
    // registration still requires the production SNS lease; it is not a pin ISI.
    let fee_domain = Domain::new(
        DomainId::try_new("universal", "universal").expect("SoraFS fee asset owning domain"),
    )
    .build(&alice);
    let alice_account = Account::new(alice.clone()).build(&alice);
    let bob_account = Account::new(bob.clone()).build(&bob);
    let world = World::with(
        [domain, fee_domain],
        [alice_account, bob_account],
        std::iter::empty::<AssetDefinition>(),
    );
    let mut state = State::new_for_testing(world, kura, live);
    let mut governance = state.gov.clone();
    governance.sorafs_provider_owners.extend(
        [
            ProviderId::new([0x51; 32]),
            ProviderId::new([0x52; 32]),
            ProviderId::new([0x53; 32]),
            ProviderId::new([0x61; 32]),
            ProviderId::new([0x62; 32]),
            ProviderId::new([0x63; 32]),
            ProviderId::new([0x71; 32]),
            ProviderId::new([0x72; 32]),
            ProviderId::new([0x73; 32]),
        ]
        .into_iter()
        .map(|provider_id| (provider_id, alice.clone())),
    );
    state.set_gov(governance);
    state
}
fn completion_anchor_header() -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 42, 0)
}
fn completion_anchor() -> ProviderIngestFinalizedAnchorV1 {
    ProviderIngestFinalizedAnchorV1 {
        height: 1,
        block_hash: *completion_anchor_header().hash().as_ref(),
    }
}
fn seed_completion_anchor(state: &State) {
    // This component fixture owns synthetic empty membership and its exact
    // header. It does not claim a signed, network-finalized completion anchor.
    state
        .block(completion_anchor_header())
        .commit_empty_block_for_testing()
        .expect("commit the component completion prefix");
}
fn completion_authority(owner: &AccountId) -> ProviderIngestCompletionAuthorityV1 {
    ProviderIngestCompletionAuthorityV1::new(
        owner.clone(),
        owner.clone(),
        ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0xA1; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [0xA2; 32],
        },
    )
}
fn seed_public_pin_fee_assets(tx: &mut iroha_core::state::StateTransaction<'_, '_>) {
    let fee_asset_id = tx.gov.sorafs_pin_fee_asset_id.clone();
    let domain_id =
        DomainId::try_new("universal", "universal").expect("SoraFS fee asset owning domain");
    if tx.world().domains().get(&domain_id).is_none() {
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&alice(), tx)
            .expect("register SoraFS fee asset domain");
    }
    let treasury = tx.gov.sorafs_pin_fee_treasury_account.clone();
    if tx.world().account(&treasury).is_err() {
        Register::account(NewAccount::new(treasury))
            .execute(&alice(), tx)
            .expect("register SoraFS fee treasury account");
    }
    if tx.world().asset_definitions().get(&fee_asset_id).is_none() {
        let definition = AssetDefinition::numeric(
            fee_asset_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id),
        );
        Register::asset_definition(definition)
            .execute(&alice(), tx)
            .expect("register SoraFS fee asset definition");
    }
    seed_pin_fee_balance(tx, &alice(), 10_000_000_000_000);
}
fn seed_pin_fee_balance(
    tx: &mut iroha_core::state::StateTransaction<'_, '_>,
    account: &AccountId,
    amount: u128,
) {
    let asset_id = AssetId::new(tx.gov.sorafs_pin_fee_asset_id.clone(), account.clone());
    Mint::asset_quantity(amount, asset_id)
        .execute(&alice(), tx)
        .expect("mint SoraFS public pin fee balance");
}
fn pin_fee_balance(
    tx: &iroha_core::state::StateTransaction<'_, '_>,
    account: &AccountId,
) -> Quantity {
    let asset_id = AssetId::new(tx.gov.sorafs_pin_fee_asset_id.clone(), account.clone());
    tx.world()
        .assets()
        .get(&asset_id)
        .map_or_else(Quantity::zero, |value| value.clone().into_inner())
}
fn assert_governed_policy_rejection(state: &State, policy: PinPolicy, expected_message: &str) {
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    bootstrap_sorafs(&mut tx);
    let alice_balance_before = pin_fee_balance(&tx, &alice());
    let treasury_account = tx.gov.sorafs_pin_fee_treasury_account.clone();
    let treasury_balance_before = pin_fee_balance(&tx, &treasury_account);
    let mut manifest = manifest_fixture(0xAA);
    manifest.pin_policy = sorafs_manifest::PinPolicy {
        min_replicas: policy.min_replicas,
        storage_class: match policy.storage_class {
            StorageClass::Hot => sorafs_manifest::StorageClass::Hot,
            StorageClass::Warm => sorafs_manifest::StorageClass::Warm,
            StorageClass::Cold => sorafs_manifest::StorageClass::Cold,
        },
        retention_epoch: policy.retention_epoch,
    };
    let submitted_digest =
        ManifestDigest::from_manifest(&manifest).expect("digest governed policy fixture");
    let err = RegisterPinManifest {
        manifest_payload: manifest.encode().expect("encode governed policy fixture"),
        alias: None,
        successor_of: None,
    }
    .execute(&alice(), &mut tx)
    .expect_err("governance policy must reject manifest registration");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert!(
            message.contains(expected_message),
            "expected `{expected_message}` in policy rejection, got {message}"
        ),
        other => panic!("expected invalid parameter error, received {other:?}"),
    }
    assert!(
        tx.world().pin_manifests().get(&submitted_digest).is_none(),
        "rejected manifest policy must not store registry state"
    );
    assert_eq!(
        pin_fee_balance(&tx, &alice()),
        alice_balance_before,
        "rejected manifest policy must not charge the submitter"
    );
    assert_eq!(
        pin_fee_balance(&tx, &treasury_account),
        treasury_balance_before,
        "rejected manifest policy must not credit the treasury"
    );
}
fn block_header(height: u64) -> iroha_data_model::block::BlockHeader {
    block_header_at(height, 0)
}
fn block_header_at(height: u64, creation_time_ms: u64) -> iroha_data_model::block::BlockHeader {
    let nz_height = NonZeroU64::new(height).expect("height must be non-zero");
    iroha_data_model::block::BlockHeader::new(nz_height, None, None, creation_time_ms, 0)
}
fn default_digest() -> ManifestDigest {
    manifest_digest_for_seed(0xAA)
}
fn manifest_fixture_with_chunk_digest(seed: u8, chunk_digest_sha3_256: [u8; 32]) -> ManifestV1 {
    let commitment = seed.max(1);
    ManifestBuilder::new()
        .root_cid(sorafs_manifest::canonical_manifest_root_cid(
            [commitment; 32],
        ))
        .dag_codec(DagCodecId(chunker_registry::MANIFEST_DAG_CODEC))
        .chunking_from_registry(chunker_registry::default_descriptor().id)
        .chunk_digest_sha3_256(chunk_digest_sha3_256)
        .por_root([commitment.wrapping_add(2).max(1); 32])
        .content_length(default_content_length())
        .car_digest([commitment.wrapping_add(1).max(1); 32])
        .car_size(default_content_length() + 4096)
        .pin_policy(sorafs_manifest::PinPolicy {
            min_replicas: default_policy().min_replicas,
            storage_class: sorafs_manifest::StorageClass::Hot,
            retention_epoch: default_policy().retention_epoch,
        })
        .governance(GovernanceProofs::default())
        .build()
        .expect("fixture manifest")
}
fn chunk_digest_for_seed(seed: u8) -> [u8; 32] {
    [seed.wrapping_add(0x23).max(1); 32]
}
fn manifest_fixture(seed: u8) -> ManifestV1 {
    manifest_fixture_with_chunk_digest(seed, chunk_digest_for_seed(seed))
}
fn manifest_payload_for_seed(seed: u8) -> Vec<u8> {
    manifest_fixture(seed)
        .encode()
        .expect("encode fixture manifest")
}
fn manifest_digest_for_seed(seed: u8) -> ManifestDigest {
    ManifestDigest::from_manifest(&manifest_fixture(seed)).expect("digest fixture manifest")
}
fn fixture_seed_for_digest(digest: ManifestDigest) -> u8 {
    (1..=u8::MAX)
        .find(|seed| manifest_digest_for_seed(*seed) == digest)
        .expect("manifest digest must belong to a fixture seed")
}
fn root_cid_for_manifest(digest: ManifestDigest) -> ManifestRootCid {
    ManifestRootCid::try_from_slice(&manifest_fixture(fixture_seed_for_digest(digest)).root_cid)
        .expect("canonical root CID")
}
fn default_chunk_digest() -> [u8; 32] {
    chunk_digest_for_seed(0xAA)
}
fn default_content_length() -> u64 {
    1_073_741_824
}
fn default_chunker() -> ChunkerProfileHandle {
    let descriptor = chunker_registry::default_descriptor();
    ChunkerProfileHandle {
        profile_id: descriptor.id.0,
        namespace: descriptor.namespace.to_owned(),
        name: descriptor.name.to_owned(),
        semver: descriptor.semver.to_owned(),
        multihash_code: descriptor.multihash_code,
    }
}
fn default_policy() -> PinPolicy {
    PinPolicy {
        min_replicas: 3,
        storage_class: StorageClass::Hot,
        // A positive manifest must outlive the mandatory automatic ingest deadline.
        // Alias rejection tests derive their out-of-range epoch from this policy.
        retention_epoch: u64::from(
            iroha_data_model::sorafs::pin_registry::SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1,
        ) + 42,
    }
}
fn bootstrap_sorafs(tx: &mut iroha_core::state::StateTransaction<'_, '_>) {
    // The caller retains this component's bounded source invocation before
    // borrowing State. Assigning a call hash here cannot create that ownership.
    let alice = alice();
    let default_domain =
        DomainId::try_new("default", "universal").expect("explicit fixture domain");
    if tx.world().domains().get(&default_domain).is_none() {
        Register::domain(Domain::new(default_domain.clone()))
            .execute(&alice, tx)
            .expect("register default domain");
    }
    if tx.world().account(&alice).is_err() {
        Register::account(NewAccount::new(alice.clone()))
            .execute(&alice, tx)
            .expect("register sorafs authority");
    }
    {
        let world = &mut tx.world;
        for perm in [
            Permission::from(CanBindSorafsAlias),
            Permission::from(CanIssueSorafsReplicationOrder),
        ] {
            world.add_account_permission(&alice, perm);
        }
    }
    seed_public_pin_fee_assets(tx);
    // Two concurrently active one-GiB manifests occur in successor tests.
    // Supply exact-profile capacity for both without weakening min_replicas.
    let consensus_epoch = tx.block_unix_timestamp_ms() / 1_000;
    let providers = iroha_core::smartcontracts::isi::sorafs::seed_eligible_auto_replication_providers_for_test(
        tx,
        &alice,
        default_policy().min_replicas,
        default_policy().storage_class,
        &default_chunker(),
        consensus_epoch,
        u64::from(iroha_data_model::sorafs::pin_registry::SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1),
        2,
    )
    .expect("seed canonical capacity and matching completion owners");
    assert_eq!(providers.len(), usize::from(default_policy().min_replicas));
    for provider_id in [
        ProviderId::new([0x51; 32]),
        ProviderId::new([0x52; 32]),
        ProviderId::new([0x53; 32]),
        ProviderId::new([0x61; 32]),
        ProviderId::new([0x62; 32]),
        ProviderId::new([0x63; 32]),
        ProviderId::new([0x71; 32]),
        ProviderId::new([0x72; 32]),
        ProviderId::new([0x73; 32]),
    ] {
        tx.world.add_account_permission(
            &alice,
            Permission::from(CanCompleteSorafsReplicationOrder { provider_id }),
        );
        let expected_current = tx
            .world()
            .provider_ingest_completion_authorities()
            .get(&provider_id)
            .cloned();
        SetProviderIngestCompletionAuthority::new(
            provider_id,
            expected_current,
            completion_authority(&alice),
        )
        .execute(&alice, tx)
        .expect("register provider completion authority");
    }
}
// Author the trusted roster before block construction, preserving automatic registration.
fn configure_council_approval(state: &mut State, council_keys: &KeyPair) {
    state.gov.sorafs_pin_policy.approval_quorum = 1;
    state.gov.sorafs_pin_policy.approval_signers =
        vec![iroha_config::parameters::actual::SorafsPinApprovalSigner {
            signer_id: "council-a".to_owned(),
            public_key: council_keys.public_key().clone(),
            valid_from_block_height: 0,
            revoked_at_block_height: None,
        }];
}
fn register_and_approve(
    tx: &mut iroha_core::state::StateTransaction<'_, '_>,
    digest: ManifestDigest,
    chunk_digest: [u8; 32],
    council_keys: &KeyPair,
) {
    let seed = fixture_seed_for_digest(digest);
    let manifest = manifest_fixture_with_chunk_digest(seed, chunk_digest);
    assert_eq!(
        ManifestDigest::from_manifest(&manifest).expect("digest registration fixture"),
        digest,
        "registration helper chunk digest must match the fixture digest"
    );
    RegisterPinManifest {
        manifest_payload: manifest.encode().expect("encode registration fixture"),
        alias: None,
        successor_of: None,
    }
    .execute(&alice(), tx)
    .expect("register manifest");
    let stored = tx
        .world()
        .pin_manifests()
        .get(&digest)
        .expect("manifest stored")
        .clone();
    let envelope = build_envelope(&stored, council_keys);
    ApprovePinManifest {
        digest,
        council_envelope: Some(envelope),
        council_envelope_digest: None,
    }
    .execute(&alice(), tx)
    .expect("approve manifest");
}
fn replication_order(
    order_id: ReplicationOrderId,
    manifest: ManifestDigest,
    providers: &[ProviderId],
    target_replicas: u16,
) -> ReplicationOrderV1 {
    let assignments = providers
        .iter()
        .map(|provider| ReplicationAssignmentV1 {
            provider_id: *provider.as_bytes(),
            slice_gib: 512,
            lane: None,
        })
        .collect();
    ReplicationOrderV1 {
        version: REPLICATION_ORDER_VERSION_V1,
        order_id: *order_id.as_bytes(),
        manifest_cid: root_cid_for_manifest(manifest).as_bytes().to_vec(),
        manifest_digest: *manifest.as_bytes(),
        chunking_profile: format!(
            "{}.{}@{}",
            default_chunker().namespace,
            default_chunker().name,
            default_chunker().semver
        ),
        target_replicas,
        assignments,
        issued_at: ORDER_ISSUED_EPOCH,
        deadline_at: ORDER_DEADLINE_EPOCH,
        sla: ReplicationOrderSlaV1 {
            ingest_deadline_secs: u32::try_from(ORDER_DEADLINE_EPOCH - ORDER_ISSUED_EPOCH)
                .expect("fixture order window fits the V1 SLA"),
            min_availability_percent_milli: 99_500,
            min_por_success_percent_milli: 98_000,
        },
        metadata: Vec::new(),
    }
}
fn alias_binding_for(
    digest: ManifestDigest,
    namespace: &str,
    name: &str,
    bound_at: u64,
    expiry_epoch: u64,
    council_keys: &KeyPair,
) -> ManifestAliasBinding {
    let binding_payload = AliasBindingV1 {
        alias: format!("{namespace}/{name}"),
        manifest_cid: root_cid_for_manifest(digest).as_bytes().to_vec(),
        bound_at,
        expiry_epoch,
    };
    let merkle_path: Vec<[u8; 32]> = Vec::new();
    let registry_root =
        alias_merkle_root(&binding_payload, &merkle_path).expect("compute alias proof merkle root");
    let generated_at_unix = 1_700_000_000;
    let expires_at_unix = generated_at_unix + 86_400;
    let mut bundle = AliasProofBundleV1 {
        binding: binding_payload,
        registry_root,
        registry_height: bound_at,
        generated_at_unix,
        expires_at_unix,
        merkle_path,
        council_signatures: Vec::new(),
    };
    let digest = alias_proof_signature_digest(&bundle);
    let signature = checked_signature(
        council_keys.private_key(),
        digest.as_ref(),
        "alias proof council signature",
    );
    let public_bytes = checked_ed25519_public_key_bytes(council_keys, "alias council public key");
    let signer: [u8; 32] = public_bytes
        .try_into()
        .expect("ed25519 public key must contain 32 bytes");
    bundle.council_signatures.push(CouncilSignature {
        signer,
        signature: signature.payload().to_vec(),
    });
    let proof = to_bytes(&bundle).expect("encode alias proof bundle");
    ManifestAliasBinding {
        name: name.to_owned(),
        namespace: namespace.to_owned(),
        proof,
    }
}
fn council_keypair() -> KeyPair {
    let secret_bytes = [0x11; 32];
    let private =
        PrivateKey::from_bytes(Algorithm::Ed25519, &secret_bytes).expect("private key bytes");
    KeyPair::from_private_key(private).expect("derive keypair")
}
fn checked_ed25519_public_key_bytes<'a>(keypair: &'a KeyPair, context: &str) -> &'a [u8] {
    let (algorithm, public_bytes) = keypair
        .public_key()
        .try_to_bytes()
        .unwrap_or_else(|err| panic!("{context} must be well-formed: {err}"));
    assert_eq!(algorithm, Algorithm::Ed25519, "{context} must be Ed25519");
    public_bytes
}
fn checked_signature(private_key: &PrivateKey, payload: &[u8], context: &str) -> Signature {
    Signature::try_new(private_key, payload)
        .unwrap_or_else(|err| panic!("{context} should sign successfully: {err}"))
}
fn build_envelope(record: &PinManifestRecord, keypair: &KeyPair) -> Vec<u8> {
    let mut sig_entry = json::Map::new();
    let signature = checked_signature(
        keypair.private_key(),
        record.digest.as_bytes(),
        "pin manifest envelope signature",
    );
    let public_bytes_hex = hex::encode(checked_ed25519_public_key_bytes(
        keypair,
        "pin fixture signer public key",
    ));
    sig_entry.insert("algorithm".into(), Value::from("ed25519"));
    sig_entry.insert("signer".into(), Value::from(public_bytes_hex));
    sig_entry.insert(
        "signature".into(),
        Value::from(hex::encode(signature.payload())),
    );
    sig_entry.insert(
        "signer_multihash".into(),
        Value::from(keypair.public_key().to_string()),
    );
    let mut envelope = json::Map::new();
    envelope.insert(
        "chunk_digest_sha3_256".into(),
        Value::from(hex::encode(record.chunk_digest_sha3_256)),
    );
    envelope.insert(
        "manifest_blake3".into(),
        Value::from(hex::encode(record.digest.as_bytes())),
    );
    envelope.insert("profile".into(), Value::from(record.chunker.to_handle()));
    envelope.insert(
        "signatures".into(),
        Value::Array(vec![Value::Object(sig_entry)]),
    );
    let mut serialized = json::to_vec_pretty(&Value::Object(envelope)).expect("serialize envelope");
    serialized.push(b'\n');
    serialized
}
fn alice() -> AccountId {
    AccountId::new(
        "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
            .parse()
            .expect("public key"),
    )
}
fn snapshot_json(
    manifest: &PinManifestRecord,
    alias: &ManifestAliasRecord,
    order: &ReplicationOrderRecord,
) -> Value {
    let manifest_obj = manifest_snapshot(manifest);
    let alias_obj = alias_snapshot(alias);
    let order_obj = order_snapshot(order);
    let mut root = json::Map::new();
    root.insert(
        "manifests".into(),
        Value::Array(vec![Value::Object(manifest_obj)]),
    );
    root.insert(
        "aliases".into(),
        Value::Array(vec![Value::Object(alias_obj)]),
    );
    root.insert(
        "replication_orders".into(),
        Value::Array(vec![Value::Object(order_obj)]),
    );
    Value::Object(root)
}
fn manifest_snapshot(manifest: &PinManifestRecord) -> json::Map {
    let mut manifest_obj = json::Map::new();
    manifest_obj.insert(
        "digest_hex".into(),
        Value::String(hex::encode(manifest.digest.as_bytes())),
    );
    manifest_obj.insert(
        "root_cid_hex".into(),
        Value::String(hex::encode(manifest.root_cid.as_bytes())),
    );
    let (status_label, status_epoch) = match manifest.status {
        PinStatus::Pending => ("pending", None),
        PinStatus::Approved(epoch) => ("approved", Some(epoch)),
        PinStatus::Retired(epoch) => ("retired", Some(epoch)),
    };
    manifest_obj.insert("status".into(), Value::String(status_label.into()));
    manifest_obj.insert(
        "status_epoch".into(),
        status_epoch.map_or(Value::Null, Value::from),
    );
    manifest_obj.insert(
        "approved_epoch".into(),
        manifest.approved_epoch.map_or(Value::Null, Value::from),
    );
    manifest_obj.insert(
        "chunk_digest_sha3_256_hex".into(),
        Value::String(hex::encode(manifest.chunk_digest_sha3_256)),
    );
    manifest_obj.insert(
        "chunker_handle".into(),
        Value::String(manifest.chunker.to_handle()),
    );
    let mut policy_obj = json::Map::new();
    policy_obj.insert(
        "min_replicas".into(),
        Value::from(manifest.policy.min_replicas),
    );
    policy_obj.insert(
        "storage_class".into(),
        Value::String(
            match manifest.policy.storage_class {
                StorageClass::Hot => "hot",
                StorageClass::Warm => "warm",
                StorageClass::Cold => "cold",
            }
            .into(),
        ),
    );
    policy_obj.insert(
        "retention_epoch".into(),
        Value::from(manifest.policy.retention_epoch),
    );
    manifest_obj.insert("policy".into(), Value::Object(policy_obj));
    manifest_obj.insert(
        "submitted_by".into(),
        Value::String(manifest.submitted_by.to_string()),
    );
    manifest_obj.insert(
        "submitted_epoch".into(),
        Value::from(manifest.submitted_epoch),
    );
    manifest_obj.insert(
        "alias_label".into(),
        manifest.alias.as_ref().map_or(Value::Null, |binding| {
            Value::String(format!("{}/{}", binding.namespace, binding.name))
        }),
    );
    manifest_obj.insert(
        "council_envelope_digest_hex".into(),
        manifest
            .council_envelope_digest
            .map_or(Value::Null, |digest| Value::String(hex::encode(digest))),
    );
    manifest_obj
}
fn alias_snapshot(alias: &ManifestAliasRecord) -> json::Map {
    let mut alias_obj = json::Map::new();
    alias_obj.insert(
        "alias_label".into(),
        Value::String(alias.alias_id().as_label()),
    );
    alias_obj.insert(
        "namespace".into(),
        Value::String(alias.binding.namespace.clone()),
    );
    alias_obj.insert("name".into(), Value::String(alias.binding.name.clone()));
    alias_obj.insert(
        "manifest_digest_hex".into(),
        Value::String(hex::encode(alias.manifest.as_bytes())),
    );
    alias_obj.insert("bound_by".into(), Value::String(alias.bound_by.to_string()));
    alias_obj.insert("bound_epoch".into(), Value::from(alias.bound_epoch));
    alias_obj.insert("expiry_epoch".into(), Value::from(alias.expiry_epoch));
    alias_obj.insert(
        "proof_b64".into(),
        Value::String(BASE64_STD.encode(&alias.binding.proof)),
    );
    alias_obj
}
fn order_snapshot(order: &ReplicationOrderRecord) -> json::Map {
    let order_payload: ReplicationOrderV1 =
        norito::decode_from_bytes(&order.canonical_order).expect("decode order payload");
    let mut order_obj = json::Map::new();
    order_obj.insert(
        "order_id_hex".into(),
        Value::String(hex::encode(order.order_id.as_bytes())),
    );
    order_obj.insert(
        "manifest_digest_hex".into(),
        Value::String(hex::encode(order.manifest_digest.as_bytes())),
    );
    order_obj.insert(
        "manifest_root_cid_hex".into(),
        Value::String(hex::encode(order.manifest_root_cid.as_bytes())),
    );
    order_obj.insert(
        "issued_by".into(),
        Value::String(order.issued_by.to_string()),
    );
    order_obj.insert("issued_epoch".into(), Value::from(order.issued_epoch));
    order_obj.insert("deadline_epoch".into(), Value::from(order.deadline_epoch));
    order_obj.insert(
        "assignment_revision".into(),
        Value::from(order.assignment_revision),
    );
    let (status_label, status_epoch) = match order.status {
        ReplicationOrderStatus::Pending => ("pending", None),
        ReplicationOrderStatus::Completed(epoch) => ("completed", Some(epoch)),
        ReplicationOrderStatus::Expired(epoch) => ("expired", Some(epoch)),
        ReplicationOrderStatus::Cancelled(epoch) => ("cancelled", Some(epoch)),
    };
    order_obj.insert("status".into(), Value::String(status_label.into()));
    order_obj.insert(
        "status_epoch".into(),
        status_epoch.map_or(Value::Null, Value::from),
    );
    let provider_completions = order
        .provider_completions
        .iter()
        .map(|completion| {
            let mut map = json::Map::new();
            map.insert(
                "provider_id_hex".into(),
                Value::String(hex::encode(completion.provider_id.as_bytes())),
            );
            map.insert(
                "completed_by".into(),
                Value::String(completion.completed_by.to_string()),
            );
            map.insert(
                "completion_epoch".into(),
                Value::from(completion.completion_epoch),
            );
            map.insert(
                "assignment_revision".into(),
                Value::from(completion.assignment_revision),
            );
            map.insert(
                "expected_owner".into(),
                Value::String(completion.completion_authority.provider_owner.to_string()),
            );
            map.insert(
                "completion_signer".into(),
                Value::String(
                    completion
                        .completion_authority
                        .completion_signer
                        .to_string(),
                ),
            );
            map.insert(
                "signer_policy_id_hex".into(),
                Value::String(hex::encode(
                    completion.completion_authority.signer_policy.policy_id,
                )),
            );
            map.insert(
                "signer_policy_revision".into(),
                Value::from(completion.completion_authority.signer_policy.revision),
            );
            map.insert(
                "signer_policy_predecessor_digest_hex".into(),
                completion
                    .completion_authority
                    .signer_policy
                    .predecessor_digest
                    .map_or(Value::Null, |digest| Value::String(hex::encode(digest))),
            );
            map.insert(
                "signer_policy_digest_hex".into(),
                Value::String(hex::encode(
                    completion.completion_authority.signer_policy.policy_digest,
                )),
            );
            map.insert(
                "finalized_height".into(),
                Value::from(completion.finalized_anchor.height),
            );
            map.insert(
                "finalized_block_hash_hex".into(),
                Value::String(hex::encode(completion.finalized_anchor.block_hash)),
            );
            Value::Object(map)
        })
        .collect();
    order_obj.insert(
        "provider_completions".into(),
        Value::Array(provider_completions),
    );
    order_obj.insert(
        "target_replicas".into(),
        Value::from(order_payload.target_replicas),
    );
    let assignments = order_payload
        .assignments
        .iter()
        .map(|assignment| {
            let mut map = json::Map::new();
            map.insert(
                "provider_id_hex".into(),
                Value::String(hex::encode(assignment.provider_id)),
            );
            map.insert("slice_gib".into(), Value::from(assignment.slice_gib));
            Value::Object(map)
        })
        .collect::<Vec<_>>();
    order_obj.insert("assignments".into(), Value::Array(assignments));
    order_obj.insert(
        "canonical_order_b64".into(),
        Value::String(BASE64_STD.encode(&order.canonical_order)),
    );
    order_obj.insert(
        "sla_ingest_deadline_secs".into(),
        Value::from(order_payload.sla.ingest_deadline_secs),
    );
    order_obj.insert(
        "sla_min_availability_percent_milli".into(),
        Value::from(order_payload.sla.min_availability_percent_milli),
    );
    order_obj.insert(
        "sla_min_por_success_percent_milli".into(),
        Value::from(order_payload.sla.min_por_success_percent_milli),
    );
    order_obj
}
fn load_fixture() -> Value {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join(FIXTURE_PATH);
    let json_str = fs::read_to_string(path).expect("fixture readable");
    norito::json::from_str(&json_str).expect("fixture parses as JSON")
}
