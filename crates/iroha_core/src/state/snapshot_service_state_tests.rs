//! Service snapshot current/undo conservation and malformed-state rejection.

use super::*;
use iroha_crypto::{KeyPair, Signature};
use iroha_data_model::sorafs::capacity::CapacityDisputeEvidence;

fn encoded(world: &World) -> String {
    let mut fields = String::new();
    serialize(world, &mut fields);
    format!("{{{}}}", &fields[1..])
}

fn restore(text: &str, world: &mut World) -> Result<(), json::Error> {
    json::from_json::<SnapshotServiceState>(text)?.restore(world)
}

pub(crate) fn service_world() -> World {
    let world = World::default();
    let provider = ProviderId::new([7; 32]);
    let dispute = CapacityDisputeId::new([8; 32]);
    let signer = KeyPair::from_seed(vec![1; 32], iroha_crypto::Algorithm::Ed25519);
    let directory = ResolverDirectoryRecordV1 {
        root_hash: [1; 32],
        record_version: 1,
        created_at_ms: 10,
        rad_count: 1,
        directory_json_sha256: [2; 32],
        previous_root: None,
        published_at_block: 1,
        published_at_unix: 0,
        proof_manifest_cid: "/ipfs/bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap(),
        builder_public_key: signer.public_key().clone(),
        builder_signature: Signature::try_new(signer.private_key(), b"structural snapshot fixture")
            .unwrap(),
    };
    // This is a structural persistence fixture. Signature admission is exercised
    // by the SoraDNS ISI suite, not asserted by this serializer regression.
    {
        let mut block = world.block();
        block.capacity_fee_ledger.insert(
            provider,
            CapacityFeeLedgerEntry {
                provider_id: provider,
                total_declared_gib: 2,
                total_utilised_gib: 1,
                storage_fee: 3_u32.into(),
                egress_fee: 4_u32.into(),
                accrued_fee: 7_u32.into(),
                expected_settlement: 8_u32.into(),
                penalty_slashed: 2_u32.into(),
                penalty_events: 1,
                last_updated_epoch: 10,
                last_window_start_epoch: 5,
                last_window_end_epoch: 10,
                last_nonce: 1,
            },
        );
        block.capacity_disputes.insert(
            dispute,
            CapacityDisputeRecord::new_pending(
                dispute,
                provider,
                [9; 32],
                None,
                0,
                10,
                "under-delivery".into(),
                None,
                CapacityDisputeEvidence {
                    digest: [4; 32],
                    media_type: None,
                    uri: None,
                    size_bytes: Some(1),
                },
                vec![1],
            ),
        );
        let mut credit = ProviderCreditRecord::new(
            provider,
            20_u32.into(),
            0_u32.into(),
            0_u32.into(),
            8_u32.into(),
            1,
            5,
            Metadata::default(),
        );
        credit.slashed = 2_u32.into();
        credit.under_delivery_strikes = 1;
        credit.last_penalty_epoch = Some(10);
        block.provider_credit_ledger.insert(provider, credit);
        block.sorafs_pricing.get_mut().notes = Some("governed H−1".into());
        block
            .soradns_directory_records
            .insert(directory.root_hash, directory.clone());
        block
            .soradns_directory_history
            .insert(0, directory.root_hash);
        *block.soradns_directory_latest.get_mut() = Some(directory.root_hash);
        *block.soradns_history_len.get_mut() = 1;
        *block.soradns_last_publish_ms.get_mut() = Some(10);
        block
            .soradns_release_signers
            .insert(signer.public_key().clone(), ());
        block.soradns_rotation_policy.get_mut().min_interval_ms = 1;
        block.soradns_directory_revocations.insert(
            [5; 32],
            ResolverRevocationRecordV1 {
                resolver_id: [5; 32],
                reason: iroha_data_model::soradns::RadRevokeReason::GovernanceAction,
                revoked_at_ms: 10,
            },
        );
        block.commit();
    }
    {
        let mut block = world.block();
        block
            .capacity_fee_ledger
            .get_mut(&provider)
            .unwrap()
            .penalty_events = 2;
        block.capacity_disputes.remove(dispute);
        block
            .provider_credit_ledger
            .get_mut(&provider)
            .unwrap()
            .under_delivery_strikes = 2;
        block.sorafs_pricing.get_mut().notes = Some("governed H".into());
        let mut next = directory;
        next.root_hash = [3; 32];
        next.previous_root = Some([1; 32]);
        next.created_at_ms = 20;
        block
            .soradns_directory_records
            .insert(next.root_hash, next.clone());
        block.soradns_directory_history.insert(1, next.root_hash);
        block
            .soradns_directory_prev_of
            .insert(next.root_hash, [1; 32]);
        *block.soradns_directory_latest.get_mut() = Some(next.root_hash);
        *block.soradns_history_len.get_mut() = 2;
        *block.soradns_last_publish_ms.get_mut() = Some(20);
        block.soradns_rotation_policy.get_mut().require_change = false;
        block
            .soradns_release_signers
            .remove(signer.public_key().clone());
        block.soradns_directory_revocations.remove([5; 32]);
        next.root_hash = [6; 32];
        next.previous_root = Some([3; 32]);
        block.soradns_directory_pending.insert(
            next.root_hash,
            PendingDirectoryDraftV1 {
                car_cid: next.proof_manifest_cid.clone(),
                directory_json_sha256: next.directory_json_sha256,
                builder_public_key: next.builder_public_key.clone(),
                builder_signature: next.builder_signature.clone(),
                record: next,
                submitted_at_ms: 21,
            },
        );
        block.commit();
    }
    world
}

#[test]
fn service_snapshot_preserves_all_fourteen_current_and_undo_envelopes() {
    let original = service_world();
    let expected = encoded(&original);
    let mut restored = World::default();
    restore(&expected, &mut restored).unwrap();
    assert_eq!(encoded(&restored), expected);
    {
        let prior = original.block_and_revert();
        let replacement = restored.block_and_revert();
        let mut left = String::new();
        let mut right = String::new();
        serialize_block(&prior, &mut left);
        serialize_block(&replacement, &mut right);
        assert_eq!(left, right);
        assert_eq!(*replacement.soradns_directory_latest.get(), Some([1; 32]));
        assert_eq!(replacement.capacity_disputes.len(), 1);
        assert_eq!(replacement.soradns_release_signers.len(), 1);
        assert_eq!(replacement.soradns_directory_revocations.len(), 1);
        assert!(replacement.soradns_directory_pending.is_empty());
    }
    assert_eq!(encoded(&restored), expected);
    restored.block_and_revert().commit();
    let replacement = encoded(&restored);
    let mut restarted = World::default();
    restore(&replacement, &mut restarted).unwrap();
    assert_eq!(encoded(&restarted), replacement);
}

#[test]
fn service_snapshot_requires_every_envelope_and_rejects_each_invalid_prior() {
    let source = service_world();
    let value: json::Value = json::from_json(&encoded(&source)).unwrap();
    let json::Value::Object(fields) = &value else {
        unreachable!()
    };
    assert_eq!(fields.len(), 14);
    for field in fields.keys() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            restore(&json::to_json(&missing).unwrap(), &mut World::default()).is_err(),
            "{field}"
        );
    }
    let mut target = World::default();
    let before = encoded(&target);
    for field in [
        "soradns_history_len",
        "soradns_directory_latest",
        "soradns_rotation_policy",
        "sorafs_pricing",
    ] {
        let mut malformed = value.clone();
        let envelope = malformed
            .as_object_mut()
            .unwrap()
            .get_mut(field)
            .unwrap()
            .as_object_mut()
            .unwrap();
        let bad = match field {
            "soradns_history_len" => json::to_value(&9_u64).unwrap(),
            "soradns_directory_latest" => json::to_value(&Some([99_u8; 32])).unwrap(),
            "soradns_rotation_policy" => {
                let policy = DirectoryRotationPolicyV1 {
                    min_interval_ms: 0,
                    ..Default::default()
                };
                json::to_value(&policy).unwrap()
            }
            _ => {
                let mut pricing = PricingScheduleRecord::launch_default();
                pricing.tiers.clear();
                json::to_value(&pricing).unwrap()
            }
        };
        envelope.insert("revert".into(), bad);
        assert!(
            restore(&json::to_json(&malformed).unwrap(), &mut target).is_err(),
            "{field}"
        );
        assert_eq!(
            encoded(&target),
            before,
            "restore is atomic on {field} failure"
        );
    }
}
