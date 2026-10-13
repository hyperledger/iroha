//! Closed role-13 custody preparation and raw committed-height readback tests.
use super::*;
use crate::{
    query::{
        release_manifest_authority::{
            ReleaseManifestCustodyErrorV1, read_current_release_manifest_custody_block_finality_v1,
            read_release_manifest_custody_at_v1,
        },
        signer_custody_history::{
            self as history, ControlAction, ControlTransition, CustodyPurpose, HistoryError,
            ManifestPurpose, ReceiptPurpose,
        },
    },
    state::StateReadOnly,
};
use iroha_data_model::block::builder::BlockBuilder;
use sorafs_manifest::signer::{
    custody::{SignerCustodyAuthorityV1, SignerCustodyBindingV1},
    custody_control::SignerCustodyPolicyV1,
    protocol::SignerKeyAlgorithmV1,
};
use std::sync::Arc;

fn software_policy(f: &Fixture) -> SignerCustodyPolicyV1 {
    software_policy_on(&f.state)
}

fn software_policy_on(state: &State) -> SignerCustodyPolicyV1 {
    let signer = KeyPair::try_from_seed(vec![9; 32], Algorithm::Ed25519).expect("signer key");
    let attester = KeyPair::try_from_seed(vec![10; 32], Algorithm::Ed25519).expect("attester key");
    SignerCustodyPolicyV1 {
        binding: SignerCustodyBindingV1 {
            chain_id: state.view().chain_id().to_string(),
            network_id: *state.view().network_id().as_bytes(),
            runtime_handle: "software://release-manifest/primary".into(),
            key_handle: "software://release-manifest/key-1".into(),
            service_id: "release-manifest-service".into(),
            administrator_id: "release-manifest-admin".into(),
            role: SignerRoleV1::ReleaseManifest,
            purpose: SignerPurposeBindingV1::ReleaseManifest {
                deployment_id: DEPLOYMENT.into(),
            },
            algorithm: SignerKeyAlgorithmV1::Ed25519,
            public_key: signer.public_key().clone(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [40; 32],
        },
        attester_authority: SignerCustodyAuthorityV1 {
            service_id: "release-custody-service".into(),
            administrator_id: "release-custody-admin".into(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [41; 32],
        },
        attester_public_key: attester.public_key().clone(),
        active_from_unix_ms: 100,
        active_until_unix_ms: 500_000,
        max_validity_ms: 120_000,
        max_anchor_age_ms: 60_000,
    }
}

fn transact(state: &mut State, now: u64, call: impl FnOnce(&mut StateTransaction<'_, '_>)) {
    let height = u64::try_from(state.view().block_hashes().len()).expect("height") + 1;
    let header = BlockHeader::new(
        height.try_into().expect("positive height"),
        state.view().latest_block_hash(),
        None,
        now,
        0,
    );
    let mut block = state.block(header.clone());
    let mut tx = block.transaction();
    call(&mut tx);
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit fixture world");
    let mut signed = BlockBuilder::new(header)
        .try_build_with_signature(
            0,
            KeyPair::try_from_seed(vec![42; 32], Algorithm::Ed25519)
                .expect("block key")
                .private_key(),
        )
        .expect("fixture block");
    signed
        .set_execution_outputs(
            Vec::new(),
            0,
            std::collections::BTreeMap::default(),
            Vec::new(),
            iroha_data_model::nexus::AxtPolicySnapshot::default(),
            std::collections::BTreeSet::default(),
            &iroha_data_model::parameter::ExecutionOutputPolicyV1::bootstrap().limits(),
        )
        .expect("complete fixture block outputs");
    let hash = signed.hash();
    let header = signed.header().clone();
    state
        .kura()
        .store_block(
            iroha_data_model::block::SharedSignedBlock::try_new(
                signed,
                &state.ivm_execution_budget(),
            )
            .expect("admit original fixture block control"),
        )
        .expect("fixture Kura row");
    state.push_block_hash_for_testing(hash);
    state.update_latest_block_header_cache_for_tests(header);
}

#[test]
fn role13_custody_preparation_is_permission_checked_unpublished_and_purpose_owned() {
    let mut f = fixture();
    let policy = software_policy(&f);
    let bytes = history::encode(&policy).expect("canonical software policy");
    let manager = f.manager.clone();
    let foreign = f.foreign.clone();
    assert_ne!(
        history::scope::<ManifestPurpose>(DEPLOYMENT),
        history::scope::<ReceiptPurpose>(DEPLOYMENT)
    );
    assert_ne!(
        ManifestPurpose::RECORD_DOMAIN,
        ReceiptPurpose::RECORD_DOMAIN
    );
    assert_eq!(
        ManifestPurpose::NAMESPACE,
        iroha_data_model::sorafs::release_manifest_authority::RELEASE_MANIFEST_AUTHORITY_NAMESPACE_V1
    );
    transact(&mut f.state, 1_000, |tx| {
        let configure = instruction(Action::Configure(bytes.clone()));
        assert!(authorized(tx.world(), &manager, &configure));
        assert!(!authorized(tx.world(), &foreign, &configure));
        let mut alien = policy.clone();
        alien.binding.purpose = SignerPurposeBindingV1::FinalPromotionProvenance {
            deployment_id: DEPLOYMENT.into(),
        };
        assert!(matches!(
            history::prepare_control::<ManifestPurpose>(
                tx,
                &manager,
                None,
                ControlTransition {
                    deployment: DEPLOYMENT,
                    expected_revision: 0,
                    expected_digest: [0; 32],
                    request_digest: [47; 32],
                    action: ControlAction::Configure(&history::encode(&alien).unwrap()),
                },
            ),
            Err(HistoryError::BindingMismatch | HistoryError::Invalid)
        ));
        let prepared = history::prepare_control::<ManifestPurpose>(
            tx,
            &manager,
            None,
            ControlTransition {
                deployment: DEPLOYMENT,
                expected_revision: 0,
                expected_digest: [0; 32],
                request_digest: [48; 32],
                action: ControlAction::Configure(&bytes),
            },
        )
        .expect("prepare exact purpose-owned control");
        assert!(
            history::read_control::<ManifestPurpose>(tx.world(), DEPLOYMENT)
                .unwrap()
                .is_none(),
            "preparation cannot publish rows"
        );
        let staged =
            history::staging_fixture::staged_control::<ManifestPurpose>(&prepared, DEPLOYMENT);
        assert_eq!(staged.record.execution.authority, manager);
        assert_eq!(staged.record.execution.height, 1);
        assert_eq!(staged.record.execution.ordinal, 0);
        assert_eq!(staged.record.execution.recorded_at_unix_ms, 1_000);
        assert_eq!(staged.state.policy, policy);
        for (path, value) in prepared {
            tx.world.smart_contract_state.insert(path, value);
        }
        let retained = history::read_control::<ManifestPurpose>(tx.world(), DEPLOYMENT)
            .expect("coherent retained control")
            .expect("one configured row");
        assert_eq!(retained.index, staged.index);
        assert_eq!(retained.record, staged.record);
    });
    let snapshot = read_release_manifest_custody_at_v1(&f.state.view(), &policy.binding, 1)
        .expect("committed-height read")
        .expect("configured role-13 control");
    assert_eq!(snapshot.control_record.revision, 1);
    assert_eq!(snapshot.control_record.execution.authority, manager);
    assert_eq!(snapshot.control.policy, policy);
    assert_eq!(snapshot.custody_anchor.height, 1);
    assert_eq!(
        snapshot.custody_anchor.state_digest,
        history::control_digest::<ManifestPurpose>(&snapshot.control_record).unwrap()
    );
}

#[test]
fn role13_committed_height_rejects_foreign_binding_and_preserves_revocation_history() {
    let mut f = fixture();
    let policy = software_policy(&f);
    let bytes = history::encode(&policy).unwrap();
    let manager = f.manager.clone();
    transact(&mut f.state, 1_000, |tx| {
        let writes = history::prepare_control::<ManifestPurpose>(
            tx,
            &manager,
            None,
            ControlTransition {
                deployment: DEPLOYMENT,
                expected_revision: 0,
                expected_digest: [0; 32],
                request_digest: [51; 32],
                action: ControlAction::Configure(&bytes),
            },
        )
        .unwrap();
        for (path, value) in writes {
            tx.world.smart_contract_state.insert(path, value);
        }
    });
    let mut foreign = policy.binding.clone();
    foreign.role = SignerRoleV1::FinalPromotionProvenance;
    foreign.purpose = SignerPurposeBindingV1::FinalPromotionProvenance {
        deployment_id: DEPLOYMENT.into(),
    };
    assert_eq!(
        read_release_manifest_custody_at_v1(&f.state.view(), &foreign, 1),
        Err(ReleaseManifestCustodyErrorV1::BindingMismatch)
    );
    assert_eq!(
        read_release_manifest_custody_at_v1(&f.state.view(), &policy.binding, 0),
        Err(ReleaseManifestCustodyErrorV1::HeightUnavailable)
    );
    assert_eq!(
        read_release_manifest_custody_at_v1(&f.state.view(), &policy.binding, 2),
        Err(ReleaseManifestCustodyErrorV1::HeightUnavailable)
    );
    transact(&mut f.state, 2_000, |tx| {
        let current = history::read_control::<ManifestPurpose>(tx.world(), DEPLOYMENT)
            .unwrap()
            .unwrap();
        let revoke = instruction(Action::Revoke(ReleaseManifestRevocationV1 {
            signer: true,
            attester: false,
        }));
        assert!(authorized(tx.world(), &manager, &revoke));
        let writes = history::prepare_control::<ManifestPurpose>(
            tx,
            &manager,
            Some(&current),
            ControlTransition {
                deployment: DEPLOYMENT,
                expected_revision: current.index.revision,
                expected_digest: current.index.digest,
                request_digest: [52; 32],
                action: ControlAction::Revoke {
                    signer: true,
                    attester: false,
                },
            },
        )
        .unwrap();
        for (path, value) in writes {
            tx.world.smart_contract_state.insert(path, value);
        }
        let latest = history::read_control::<ManifestPurpose>(tx.world(), DEPLOYMENT)
            .unwrap()
            .unwrap();
        assert!(matches!(
            history::prepare_control::<ManifestPurpose>(
                tx,
                &manager,
                Some(&latest),
                ControlTransition {
                    deployment: DEPLOYMENT,
                    expected_revision: current.index.revision,
                    expected_digest: current.index.digest,
                    request_digest: [52; 32],
                    action: ControlAction::Revoke {
                        signer: true,
                        attester: false,
                    },
                },
            ),
            Err(HistoryError::Conflict)
        ));
    });
    let earlier = read_release_manifest_custody_at_v1(&f.state.view(), &policy.binding, 1)
        .unwrap()
        .unwrap();
    let revoked = read_release_manifest_custody_at_v1(&f.state.view(), &policy.binding, 2)
        .unwrap()
        .unwrap();
    assert_eq!(earlier.control_record.revision, 1);
    assert!(!earlier.control.signer_revoked);
    assert_eq!(revoked.control_record.revision, 2);
    assert!(revoked.control.signer_revoked);
    assert_ne!(
        earlier.custody_anchor.state_digest,
        revoked.custody_anchor.state_digest
    );
}

#[test]
fn role13_custody_rotation_cannot_reuse_retired_signer_key() {
    let mut f = fixture();
    let original = software_policy(&f);
    let original_bytes = history::encode(&original).unwrap();
    let manager = f.manager.clone();
    transact(&mut f.state, 1_000, |tx| {
        let writes = history::prepare_control::<ManifestPurpose>(
            tx,
            &manager,
            None,
            ControlTransition {
                deployment: DEPLOYMENT,
                expected_revision: 0,
                expected_digest: [0; 32],
                request_digest: [61; 32],
                action: ControlAction::Configure(&original_bytes),
            },
        )
        .unwrap();
        for (path, value) in writes {
            tx.world.smart_contract_state.insert(path, value);
        }
    });
    let mut rotated = original.clone();
    rotated.binding.public_key = KeyPair::try_from_seed(vec![11; 32], Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .clone();
    rotated.binding.key_revision = 2;
    rotated.binding.key_handle = "software://release-manifest/key-2".into();
    let rotated_bytes = history::encode(&rotated).unwrap();
    transact(&mut f.state, 2_000, |tx| {
        let first = history::read_control::<ManifestPurpose>(tx.world(), DEPLOYMENT)
            .unwrap()
            .unwrap();
        let writes = history::prepare_control::<ManifestPurpose>(
            tx,
            &manager,
            Some(&first),
            ControlTransition {
                deployment: DEPLOYMENT,
                expected_revision: first.index.revision,
                expected_digest: first.index.digest,
                request_digest: [62; 32],
                action: ControlAction::Configure(&rotated_bytes),
            },
        )
        .unwrap();
        for (path, value) in writes {
            tx.world.smart_contract_state.insert(path, value);
        }
        let current = history::read_control::<ManifestPurpose>(tx.world(), DEPLOYMENT)
            .unwrap()
            .unwrap();
        let mut reused = rotated.clone();
        reused.binding.public_key = original.binding.public_key.clone();
        reused.binding.key_revision = 3;
        reused.binding.key_handle = "software://release-manifest/key-3".into();
        let reused_bytes = history::encode(&reused).unwrap();
        assert!(matches!(
            history::prepare_control::<ManifestPurpose>(
                tx,
                &manager,
                Some(&current),
                ControlTransition {
                    deployment: DEPLOYMENT,
                    expected_revision: current.index.revision,
                    expected_digest: current.index.digest,
                    request_digest: [63; 32],
                    action: ControlAction::Configure(&reused_bytes),
                },
            ),
            Err(HistoryError::Generation)
        ));
    });
    assert_eq!(
        read_release_manifest_custody_at_v1(&f.state.view(), &rotated.binding, 2)
            .unwrap()
            .unwrap()
            .control_record
            .revision,
        2
    );
    assert_eq!(
        read_release_manifest_custody_at_v1(&f.state.view(), &original.binding, 2),
        Err(ReleaseManifestCustodyErrorV1::BindingMismatch)
    );
}

#[test]
fn role13_current_raw_custody_requires_exact_block_finality_and_remains_non_authoritative() {
    use crate::query::signer_check::fixture::{chain, commit, commit_uncertified};
    let mut chain = chain(fixture_world());
    let state = Arc::clone(chain.state());
    let policy = software_policy_on(&state);
    let bytes = history::encode(&policy).expect("canonical software policy");
    let manager = account(1);
    // Fixture-only custody preparation, published into the World block 2 is read at.
    chain.setup_world_at(1_000, |tx| {
        let writes = history::prepare_control::<ManifestPurpose>(
            tx,
            &manager,
            None,
            ControlTransition {
                deployment: DEPLOYMENT,
                expected_revision: 0,
                expected_digest: [0; 32],
                request_digest: [91; 32],
                action: ControlAction::Configure(&bytes),
            },
        )
        .expect("fixture-only custody preparation");
        for (path, value) in writes {
            tx.world.smart_contract_state.insert(path, value);
        }
    });
    let read = |binding: &SignerCustodyBindingV1, height| {
        read_current_release_manifest_custody_block_finality_v1(&state.view(), binding, height)
    };
    // Block 2 is committed and durable, but its local CommitQC does not verify.
    assert!(commit(&mut chain, 1_000, Vec::new()).is_empty());
    let original = chain.committed(2);
    chain.corrupt_local_quorum_for_test(2, crate::sumeragi::test_chain::Signers::BelowQuorum);
    assert_eq!(
        read(&policy.binding, 2),
        Err(ReleaseManifestCustodyErrorV1::FinalityUnavailable),
        "a committed row and durable block do not replace the CommitQC"
    );
    // Retain and recover the actual original QC before advancing: the complete
    // certificate prefix is mandatory for the current custody read.
    state
        .kura()
        .corrupt_commit_certificate_for_testing(
            std::num::NonZeroUsize::new(2).unwrap(),
            Some(
                original
                    .block()
                    .commit_certificate()
                    .unwrap()
                    .commit_qc()
                    .to_vec(),
            ),
        )
        .unwrap();
    assert_eq!(
        chain
            .committed(2)
            .block()
            .executed_block_wire_identity()
            .unwrap(),
        original.block().executed_block_wire_identity().unwrap()
    );
    // A certified successor finalizes the current raw row.
    assert!(commit(&mut chain, 1_500, Vec::new()).is_empty());
    let current = read(&policy.binding, 3)
        .expect("same-State certified block finality")
        .expect("fixture-only raw custody row");
    assert_eq!(current.custody().control_record.deployment_id, DEPLOYMENT);
    assert_eq!(current.block_finality().height(), 3);
    assert_eq!(
        current.block_finality().context_id(),
        chain.committed(3).id()
    );
    assert_eq!(
        current.block_finality().block_hash(),
        current.custody().custody_anchor.block_hash
    );
    assert!(
        !history::prefix_has_any::<ManifestPurpose>(state.view().world(), DEPLOYMENT, "operation")
            .unwrap(),
        "block finality does not create a role-13 operation journal"
    );
    let mut foreign_deployment = policy.binding.clone();
    foreign_deployment.purpose = SignerPurposeBindingV1::ReleaseManifest {
        deployment_id: "release-secondary".into(),
    };
    assert!(read(&foreign_deployment, 3).unwrap().is_none());
    let mut foreign_network = policy.binding.clone();
    foreign_network.network_id = [0xA5; 32];
    assert_eq!(
        read(&foreign_network, 3),
        Err(ReleaseManifestCustodyErrorV1::BindingMismatch)
    );
    assert!(commit_uncertified(&mut chain, 2_000, Vec::new()).is_empty());
    assert_eq!(
        read(&policy.binding, 3),
        Err(ReleaseManifestCustodyErrorV1::StaleHeight),
        "old finality cannot authorize a current raw custody read"
    );
    assert_eq!(
        read(&policy.binding, 4),
        Err(ReleaseManifestCustodyErrorV1::FinalityUnavailable),
        "current custody cannot borrow an earlier block's CommitQC"
    );
}
