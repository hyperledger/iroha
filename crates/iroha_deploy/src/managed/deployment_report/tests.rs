//! Reporting preserves original execution and never promotes historical parent status.

use super::*;
use iroha_contract_deploy::AppliedEvidence;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    private_dataspace::PrivateDataspaceCursor,
    smart_contract::{ContractAddress, ContractAlias},
};
use iroha_fs::PublishMode;
use iroha_model_base::topology::DataSpaceId;

fn global_fixture() -> (tempfile::TempDir, ManagedStore, ManagedDeploymentTarget) {
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, _) =
        super::super::tests::fixture(&temporary.path().join("state"), "local");
    let retained = generation::read(&directory).unwrap();
    let target = store
        .capture_deployment(&retained.prepared.context)
        .unwrap();
    (temporary, store, target)
}

fn private_fixture() -> (tempfile::TempDir, ManagedStore, ManagedDeploymentTarget) {
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("state")).unwrap();
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    let directory = networks.create_child("private").unwrap();
    let bundle = directory.create_child(generation::DIRECTORY).unwrap();
    let spec = super::super::tests::private_spec();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared =
        crate::localnet::prepare_private_root("private", bundle.path(), &ports, &spec).unwrap();
    let pin = store::pin_binary(&std::env::current_exe().unwrap()).unwrap();
    let retained = RetainedLocalnet {
        root_kind: RootKind::Private { spec },
        prepared,
        launcher: pin.clone(),
        daemon: pin,
        startup_timeout_ms: 30000,
    };
    bundle
        .write_atomic(
            MANIFEST,
            &encode(&retained).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let target = store
        .capture_deployment(&retained.prepared.context)
        .unwrap();
    (temporary, store, target)
}

fn receipt(target: &ManagedDeploymentTarget) -> DeploymentReceipt {
    let selected = &target.prepared.context;
    let chain_discriminant = if matches!(target.root_kind, RootKind::Private { .. }) {
        target
            .prepared
            .context
            .load_client_config()
            .unwrap()
            .account_chain_discriminant
    } else {
        753
    };
    let _profile = ChainDiscriminantGuard::enter(chain_discriminant);
    let authority =
        iroha_data_model::account::AccountId::parse_encoded(&selected.account_id).unwrap();
    let dataspace = DataSpaceId::new(selected.dataspace_id);
    let address =
        ContractAddress::derive(&target.execution.network_id, &authority, 0, dataspace).unwrap();
    let commit = AppliedEvidence {
        hash: Hash::new(b"applied-local-deployment").to_string(),
        terminal_kind: "Applied".into(),
        block_height: 8,
        scope: "global".into(),
        resolved_from: "state".into(),
        charge: None,
    };
    DeploymentReceipt {
        version: 1,
        network_id: target.execution.network_id,
        chain_id: selected.chain_id.clone(),
        chain_discriminant,
        authority,
        contract_alias: ContractAlias::from_components("report", None, &selected.dataspace_alias)
            .unwrap(),
        contract_subject_account: address.subject_id(),
        contract_address: address,
        dataspace_id: dataspace,
        code_hash: Hash::new(b"report-code"),
        abi_hash: Hash::new(b"report-abi"),
        stages: vec![commit.clone()],
        commit,
        readback_block_height: 8,
        readback_block_hash: Hash::new(b"readback-block").to_string(),
        stored_artifact_matches: true,
    }
}

#[test]
fn global_report_preserves_service_receipt_without_parent_observation() {
    let _guard = super::super::native_test_guard();
    let (_temporary, store, target) = global_fixture();
    let original = receipt(&target);
    let original_json = original.to_json().unwrap();
    let report = target
        .finish_with(original, "original-journal".into(), || {
            panic!("global root has no parent")
        })
        .unwrap();
    assert_eq!(report.execution_summary(), "Applied on localnet local");
    assert!(report.parent_summary().is_none());
    assert!(report.parent.is_none());
    let json = report.to_json().unwrap();
    assert_eq!(
        json.get("status").and_then(|value| value.as_str()),
        Some("applied")
    );
    assert_eq!(json.get("receipt"), Some(&original_json));
    assert_eq!(
        json.get("journal").and_then(|value| value.as_str()),
        Some("original-journal")
    );
    target.revalidate_generation(&store).unwrap();
}

#[test]
fn lifecycle_guidance_keeps_applied_receipt_and_original_journal_unchanged() {
    let _guard = super::super::native_test_guard();
    let (_temporary, _store, target) = global_fixture();
    let original = receipt(&target);
    let original_json = original.to_json().unwrap();
    for recovered in [false, true] {
        let mut report = target
            .finish_with(original.clone(), "original-journal".into(), || {
                panic!("no parent")
            })
            .unwrap();
        report.lifecycle = Some(
            iroha_contract_deploy::LifecycleHook {
                name: "hajimari".into(),
                params: vec![iroha_contract_deploy::LifecycleParameter {
                    name: "start".into(),
                    type_name: "int".into(),
                }],
            }
            .guidance(recovered),
        );
        let json = report.to_json().unwrap();
        assert_eq!(
            json.get("status").and_then(|value| value.as_str()),
            Some("applied")
        );
        assert_eq!(json.get("receipt"), Some(&original_json));
        assert_eq!(
            json.get("journal").and_then(|value| value.as_str()),
            Some("original-journal")
        );
        assert_eq!(
            json.get("lifecycle").unwrap(),
            &norito::json::to_value(report.lifecycle.as_ref().unwrap()).unwrap()
        );
        assert_eq!(report.execution_summary(), "Applied on localnet local");
    }
}

#[test]
fn signed_private_capture_keeps_local_applied_when_generation_changes() {
    let _guard = super::super::native_test_guard();
    let (_temporary, store, target) = private_fixture();
    let original = receipt(&target);
    let original_json = original.to_json().unwrap();
    let report = target
        .finish(&store, original.clone(), "private-journal".into())
        .unwrap();
    assert_eq!(
        report.execution.root_scope,
        super::super::tests::private_spec().scope()
    );
    assert!(matches!(
        report.parent.as_ref().unwrap().observation,
        ManagedParentObservation::NotConfigured
    ));
    assert!(
        report
            .execution_summary()
            .starts_with("Applied on private dataspace ")
    );
    assert_eq!(
        report.receipt.commit.scope, "global",
        "transaction scope is not parent inclusion"
    );

    let mut replacement = generation::read(&target.directory).unwrap();
    replacement.prepared.context.network_id =
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"replacement")))
            .to_string();
    target
        .generation
        .write_atomic(
            MANIFEST,
            &encode(&replacement).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(target.revalidate_generation(&store).is_err());
    let report = target
        .finish(&store, original, "private-journal".into())
        .unwrap();
    let parent = report.parent.as_ref().unwrap();
    assert_eq!(parent.child_network_id, target.execution.network_id);
    assert_eq!(
        parent.parent_network_id,
        super::super::tests::private_spec().parent_network_id
    );
    assert!(matches!(
        parent.observation,
        ManagedParentObservation::Unavailable { .. }
    ));
    assert_eq!(
        report.to_json().unwrap().get("receipt"),
        Some(&original_json)
    );
    assert_eq!(
        report.parent_summary().unwrap(),
        "Parent attachment observation is unavailable"
    );
}

#[test]
fn historical_receipt_is_separate_even_when_height_matches_or_parent_is_unavailable() {
    let _guard = super::super::native_test_guard();
    let (_temporary, _store, target) = private_fixture();
    let status = ManagedAttachmentStatus {
        network: "installed".into(),
        stage: ManagedAttachmentPhase::Unavailable,
        wallet_status: None,
        local_successor: Some(PrivateDataspaceCursor {
            height: 9,
            consensus_hash: [1; 32],
            result: [2; 32],
        }),
        parent_confirmed: Some(ManagedConfirmedAnchor {
            parent_height: u64::MAX,
            child: PrivateDataspaceCursor {
                height: 8,
                consensus_hash: [3; 32],
                result: [4; 32],
            },
        }),
        failure: Some(crate::managed::ManagedAttachmentFailure::ParentUnavailable),
    };
    let report = target
        .finish_with(receipt(&target), "journal".into(), || {
            Ok(Some(status.clone()))
        })
        .unwrap();
    let parent = report.parent.as_ref().unwrap();
    assert_eq!(
        parent.observation,
        ManagedParentObservation::Observed {
            status: status.clone()
        }
    );
    assert_eq!(
        report.parent_summary().unwrap(),
        format!(
            "Historical parent receipt: child block #8 in parent block #{}",
            u64::MAX
        )
    );
    let encoded = norito::json::to_vec(parent).unwrap();
    assert_eq!(
        norito::json::from_slice::<ManagedParentReport>(&encoded).unwrap(),
        *parent
    );
    let json = report.to_json().unwrap();
    assert!(json.get("anchored").is_none());
    let parent_json = json.get("parent").unwrap();
    assert!(parent_json.get("anchored").is_none());
    let mut unconfirmed = status;
    unconfirmed.stage = ManagedAttachmentPhase::Attached;
    unconfirmed.parent_confirmed = None;
    let unconfirmed = target
        .finish_with(receipt(&target), "journal".into(), || Ok(Some(unconfirmed)))
        .unwrap();
    assert_eq!(
        unconfirmed.parent_summary().unwrap(),
        "Parent attachment: awaiting verified receipt; no verified parent receipt"
    );
    let failed = target
        .finish_with(receipt(&target), "journal".into(), || {
            Err(Error::Invalid(
                "sensitive diagnostic must not escape".into(),
            ))
        })
        .unwrap();
    let encoded = norito::json::to_string(&failed.to_json().unwrap()).unwrap();
    assert!(!encoded.contains("sensitive diagnostic"));
    assert!(matches!(
        failed.parent.unwrap().observation,
        ManagedParentObservation::Unavailable { .. }
    ));
}

#[test]
fn receipt_binding_rejects_foreign_identity_before_parent_observation() {
    let _guard = super::super::native_test_guard();
    let (_temporary, _store, target) = global_fixture();
    let alterations: [fn(&mut DeploymentReceipt); 4] = [
        |receipt: &mut DeploymentReceipt| {
            receipt.network_id =
                NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"foreign")))
        },
        |receipt: &mut DeploymentReceipt| receipt.dataspace_id = DataSpaceId::new(9),
        |receipt: &mut DeploymentReceipt| receipt.chain_id = "foreign".into(),
        |receipt: &mut DeploymentReceipt| receipt.authority = iroha_test_samples::BOB_ID.clone(),
    ];
    for alter in alterations {
        let mut foreign = receipt(&target);
        alter(&mut foreign);
        assert!(
            target
                .finish_with(foreign, "journal".into(), || panic!(
                    "foreign receipt cannot observe parent"
                ))
                .is_err()
        );
    }
    let mut selected = target.prepared.context.clone();
    selected.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"different-selection",
    )))
    .to_string();
    assert!(_store.capture_deployment(&selected).is_err());
}
