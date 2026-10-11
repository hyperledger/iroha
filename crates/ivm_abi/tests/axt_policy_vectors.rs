//! Golden Norito fixtures for AXT descriptor/handle/policy encodings plus validation edge cases.
#[path = "fixtures/axt_golden.rs"]
mod axt_golden;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::nexus::{
    AssetHandle, AxtAssetIncarnationV1, AxtBinding, AxtDescriptor, AxtHandleCounterRecord,
    AxtHandleIssuerContextV1, AxtHandleReplayKey, AxtPolicyBinding, AxtPolicyEntry,
    AxtPolicySnapshot, AxtTouchFragment, AxtTouchSpec, AxtValidationError, GroupBinding,
    HandleBudget, HandleSubject, TouchManifest, UniversalAccountId, validate_descriptor,
};
use iroha_data_model::{NetworkId, asset::id::AssetDefinitionId, block::BlockHeader};
use iroha_model_base::domain::DomainId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::numeric::Quantity;
use ivm_abi::axt;
fn assert_bytes_match(name: &str, actual: &[u8], expected: &[u8]) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "{name} length mismatch: {} vs {}",
        actual.len(),
        expected.len()
    );
    if let Some((idx, (lhs, rhs))) = actual
        .iter()
        .zip(expected.iter())
        .enumerate()
        .find(|(_, (lhs, rhs))| lhs != rhs)
    {
        panic!("{name} mismatch at byte {idx}: actual {lhs:#04x} expected {rhs:#04x}");
    }
}
fn sample_descriptor() -> AxtDescriptor {
    let ds_a = DataSpaceId::new(7);
    let ds_b = DataSpaceId::new(13);
    AxtDescriptor {
        dsids: vec![ds_a, ds_b],
        touches: vec![
            AxtTouchSpec {
                dsid: ds_a,
                read: vec!["audit/".into(), "orders/".into()],
                write: vec!["ledger/".into()],
            },
            AxtTouchSpec {
                dsid: ds_b,
                read: vec!["reports/".into()],
                write: vec!["aggregates/".into(), "dashboards/".into()],
            },
        ],
    }
}
fn sample_binding(descriptor: &AxtDescriptor) -> AxtBinding {
    validate_descriptor(descriptor).expect("sample descriptor must be canonical");
    let ivm_descriptor = axt::AxtDescriptor {
        dsids: descriptor.dsids.clone(),
        touches: descriptor
            .touches
            .iter()
            .map(|touch| axt::AxtTouchSpec {
                dsid: touch.dsid,
                read: touch.read.clone(),
                write: touch.write.clone(),
            })
            .collect(),
    };
    let binding = axt::compute_binding(&ivm_descriptor).expect("binding");
    AxtBinding::new(binding)
}
fn encoded_account(public_key_hex: &str) -> String {
    iroha_data_model::account::AccountId::new(public_key_hex.parse().expect("public key"))
        .to_string()
}
fn sample_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("axt", "universal").expect("asset domain"),
        "rose".parse().expect("asset name"),
    )
}
fn sample_issuer_context() -> AxtHandleIssuerContextV1 {
    let network_id = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"axt-policy-vectors-network"),
    ));
    let registration_header_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"axt-policy-vectors-asset-registration-header",
    ));
    let execution_identity = Hash::new(b"axt-policy-vectors-asset-registration-execution");
    AxtHandleIssuerContextV1 {
        network_id,
        asset_dsid: DataSpaceId::new(7),
        asset_definition_incarnation: AxtAssetIncarnationV1::derive(
            &network_id,
            &sample_asset_definition_id(),
            &registration_header_hash,
            &execution_identity,
            0,
        ),
        issuer: UniversalAccountId::from_hash(Hash::new(b"axt-policy-vectors-issuer")),
        issuer_manifest_root: [0x22; 32],
        code_root: Hash::new(b"axt-policy-vectors-code").into(),
        abi_version: 1,
        abi_hash: ivm_abi::syscalls::compute_abi_hash(ivm_abi::SyscallPolicy::AbiV1),
    }
}
fn sample_handle(binding: AxtBinding) -> AssetHandle {
    AssetHandle {
        asset_definition_id: sample_asset_definition_id(),
        scope: vec!["register".into(), "transfer".into()],
        subject: HandleSubject {
            account: encoded_account(
                "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            ),
            origin_dsid: Some(DataSpaceId::new(7)),
        },
        budget: HandleBudget {
            remaining: Quantity::from(900_u64),
            per_use: Some(Quantity::from(300_u64)),
        },
        handle_era: 4,
        sub_nonce: 6,
        group_binding: GroupBinding {
            composability_group_id: vec![0xAB, 0xCD, 0xEF],
            epoch_id: 9,
        },
        target_lane: LaneId::new(5),
        axt_binding: binding,
        manifest_view_root: [0x22; 32],
        expiry_slot: 77,
        max_clock_skew_ms: Some(15),
        issuer_context: sample_issuer_context(),
        issuer_signature: iroha_crypto::Signature::from_bytes(&[1_u8; 64]),
    }
}
fn sample_policy_snapshot() -> AxtPolicySnapshot {
    let entries = vec![AxtPolicyBinding {
        dsid: DataSpaceId::new(7),
        policy: AxtPolicyEntry {
            manifest_root: [0x22; 32],
            target_lane: LaneId::new(5),
            active_handle_era: 3,
            next_handle_counter: 5,
            current_slot: 55,
        },
    }];
    AxtPolicySnapshot {
        version: AxtPolicySnapshot::compute_version(&entries),
        entries,
    }
}
fn sample_handle_counter() -> AxtHandleCounterRecord {
    AxtHandleCounterRecord::try_from_parts(7, 9).expect("valid permanent AXT ratchet fixture")
}
fn sample_handle_replay_key() -> AxtHandleReplayKey {
    let descriptor = sample_descriptor();
    let handle = sample_handle(sample_binding(&descriptor));
    AxtHandleReplayKey::from_handle(DataSpaceId::new(7), &handle)
}
#[test]
fn descriptor_roundtrip_matches_golden() {
    let descriptor = sample_descriptor();
    let bytes = norito::to_bytes(&descriptor).expect("encode descriptor");
    assert_bytes_match("descriptor", &bytes, axt_golden::AXT_DESCRIPTOR);
    let decoded: AxtDescriptor =
        norito::decode_from_bytes(axt_golden::AXT_DESCRIPTOR).expect("decode descriptor fixture");
    assert_eq!(decoded, descriptor);
    assert_eq!(validate_descriptor(&descriptor), Ok(()));
}
#[test]
fn asset_handle_roundtrip_matches_golden() {
    let descriptor = sample_descriptor();
    let binding = sample_binding(&descriptor);
    let handle = sample_handle(binding);
    let bytes = norito::to_bytes(&handle).expect("encode handle");
    let decoded: AssetHandle =
        norito::decode_from_bytes(axt_golden::AXT_HANDLE).expect("decode handle fixture");
    assert_eq!(
        decoded.issuer_context.abi_hash, handle.issuer_context.abi_hash,
        "AXT handle fixture must bind the current canonical ABI-v1 surface",
    );
    assert_bytes_match("handle", &bytes, axt_golden::AXT_HANDLE);
    assert_eq!(decoded, handle);
}
#[test]
fn policy_snapshot_roundtrip_matches_golden() {
    let snapshot = sample_policy_snapshot();
    let bytes = norito::to_bytes(&snapshot).expect("encode policy snapshot");
    assert_bytes_match("policy snapshot", &bytes, axt_golden::AXT_POLICY);
    let decoded: AxtPolicySnapshot =
        norito::decode_from_bytes(axt_golden::AXT_POLICY).expect("decode policy fixture");
    assert_eq!(decoded, snapshot);
}
#[test]
fn handle_counter_roundtrip_matches_golden() {
    let counter = sample_handle_counter();
    let bytes = norito::to_bytes(&counter).expect("encode handle counter ratchet");
    assert_bytes_match(
        "handle counter ratchet",
        &bytes,
        axt_golden::AXT_HANDLE_COUNTER,
    );
    let decoded: AxtHandleCounterRecord = norito::decode_from_bytes(axt_golden::AXT_HANDLE_COUNTER)
        .expect("decode handle counter fixture");
    decoded.validate().expect("validate decoded handle counter");
    assert_eq!(decoded, counter);
}
#[test]
fn handle_replay_key_roundtrip_matches_golden() {
    let key = sample_handle_replay_key();
    let bytes = norito::to_bytes(&key).expect("encode handle replay key");
    assert_bytes_match(
        "handle replay key",
        &bytes,
        axt_golden::AXT_HANDLE_REPLAY_KEY,
    );
    let decoded: AxtHandleReplayKey = norito::decode_from_bytes(axt_golden::AXT_HANDLE_REPLAY_KEY)
        .expect("decode handle replay key fixture");
    decoded.validate().expect("validate decoded replay key");
    assert_eq!(decoded, key);
}
#[test]
fn descriptor_validation_errors_are_stable() {
    let empty = AxtDescriptor {
        dsids: vec![],
        touches: vec![],
    };
    assert!(matches!(
        validate_descriptor(&empty),
        Err(AxtValidationError::EmptyDataspaceList)
    ));
    let dup_id = AxtDescriptor {
        dsids: vec![DataSpaceId::new(2), DataSpaceId::new(2)],
        touches: vec![],
    };
    assert!(matches!(
        validate_descriptor(&dup_id),
        Err(AxtValidationError::DuplicateDataspaceId(id)) if id == DataSpaceId::new(2)
    ));
    let undeclared_touch = AxtDescriptor {
        dsids: vec![DataSpaceId::new(1)],
        touches: vec![AxtTouchSpec {
            dsid: DataSpaceId::new(3),
            read: vec![],
            write: vec![],
        }],
    };
    assert!(matches!(
        validate_descriptor(&undeclared_touch),
        Err(AxtValidationError::TouchUndeclaredDataspace(id)) if id == DataSpaceId::new(3)
    ));
    let duplicate_touch = AxtDescriptor {
        dsids: vec![DataSpaceId::new(5)],
        touches: vec![
            AxtTouchSpec {
                dsid: DataSpaceId::new(5),
                read: vec![],
                write: vec![],
            },
            AxtTouchSpec {
                dsid: DataSpaceId::new(5),
                read: vec![],
                write: vec![],
            },
        ],
    };
    assert!(matches!(
        validate_descriptor(&duplicate_touch),
        Err(AxtValidationError::DuplicateTouch(id)) if id == DataSpaceId::new(5)
    ));
}
#[test]
#[ignore = "utility for regenerating golden vectors"]
fn print_golden_vectors() {
    let descriptor = sample_descriptor();
    let binding = sample_binding(&descriptor);
    let handle = sample_handle(binding);
    let snapshot = sample_policy_snapshot();
    let counter = sample_handle_counter();
    let replay_key = AxtHandleReplayKey::from_handle(DataSpaceId::new(7), &handle);
    let descriptor_bytes = norito::to_bytes(&descriptor).expect("encode descriptor");
    let handle_bytes = norito::to_bytes(&handle).expect("encode handle");
    let snapshot_bytes = norito::to_bytes(&snapshot).expect("encode snapshot");
    println!("descriptor: {}", hex::encode(descriptor_bytes));
    println!("handle: {}", hex::encode(handle_bytes));
    println!("policy: {}", hex::encode(snapshot_bytes));
    println!(
        "handle counter: {}",
        hex::encode(norito::to_bytes(&counter).expect("encode handle counter ratchet"))
    );
    println!(
        "handle replay key: {}",
        hex::encode(norito::to_bytes(&replay_key).expect("encode handle replay key"))
    );
    let touch_fragment = AxtTouchFragment {
        dsid: descriptor.dsids[0],
        manifest: TouchManifest {
            read: vec!["orders/ready".into()],
            write: vec!["ledger/ready".into()],
        },
    };
    let snapshot_entries = snapshot.entries.clone();
    let snapshot_fragment = AxtPolicySnapshot {
        version: AxtPolicySnapshot::compute_version(&snapshot_entries),
        entries: snapshot_entries,
    };
    println!(
        "touch fragment: {}",
        hex::encode(
            norito::to_bytes(&touch_fragment)
                .expect("encode touch fragment")
                .as_slice(),
        )
    );
    println!(
        "snapshot fragment: {}",
        hex::encode(
            norito::to_bytes(&snapshot_fragment)
                .expect("encode snapshot fragment")
                .as_slice(),
        )
    );
}
