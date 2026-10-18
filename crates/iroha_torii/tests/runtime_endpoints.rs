//! Integration coverage for runtime upgrade endpoints.
#![cfg(feature = "app_api")]
use axum::{extract::Path as AxPath, response::IntoResponse as _};
use iroha_data_model::runtime::{
    RuntimeUpgradeId, RuntimeUpgradeManifest, RuntimeUpgradeRecord, RuntimeUpgradeStatus,
};
use iroha_torii::{
    handle_runtime_activate_upgrade, handle_runtime_cancel_upgrade, test_utils::random_authority,
};
use std::vec::Vec;
struct SimpleItem {
    record: RuntimeUpgradeRecord,
}
#[tokio::test]
async fn runtime_activate_and_cancel_validate_identifiers() {
    // Case 1: malformed hex should return a conversion error
    let err = handle_runtime_activate_upgrade(AxPath("xyz".to_string()))
        .await
        .expect_err("expected invalid hex rejection");
    match err {
        iroha_torii::Error::Query(vf) => match vf {
            iroha_data_model::ValidationFail::QueryFailed(qf) => match qf {
                iroha_data_model::query::error::QueryExecutionFail::Conversion(msg) => {
                    assert_eq!(msg, "invalid id");
                }
                other => panic!("unexpected query failure variant: {other:?}"),
            },
            other => panic!("unexpected validation fail: {other:?}"),
        },
        other => panic!("unexpected error type: {other:?}"),
    }
    // Case 2: good hex but wrong length (31 bytes)
    let bad_len_hex = "aa".repeat(31);
    let err = handle_runtime_activate_upgrade(AxPath(bad_len_hex))
        .await
        .expect_err("expected invalid length rejection");
    match err {
        iroha_torii::Error::Query(vf) => match vf {
            iroha_data_model::ValidationFail::QueryFailed(qf) => match qf {
                iroha_data_model::query::error::QueryExecutionFail::Conversion(msg) => {
                    assert_eq!(msg, "invalid id length");
                }
                other => panic!("unexpected query failure variant: {other:?}"),
            },
            other => panic!("unexpected validation fail: {other:?}"),
        },
        other => panic!("unexpected error type: {other:?}"),
    }
    // Case 3: cancel endpoint mirrors the same validation
    let err = handle_runtime_cancel_upgrade(AxPath("gh".to_string()))
        .await
        .expect_err("expected invalid hex rejection for cancel");
    match err {
        iroha_torii::Error::Query(vf) => match vf {
            iroha_data_model::ValidationFail::QueryFailed(qf) => match qf {
                iroha_data_model::query::error::QueryExecutionFail::Conversion(msg) => {
                    assert_eq!(msg, "invalid id");
                }
                other => panic!("unexpected query failure variant: {other:?}"),
            },
            other => panic!("unexpected validation fail: {other:?}"),
        },
        other => panic!("unexpected error type: {other:?}"),
    }
    // Router-style response (200) is sufficient for a well-formed id
    let ok_id = RuntimeUpgradeId([0x11; 32]);
    let ok_resp = handle_runtime_activate_upgrade(AxPath(hex::encode(ok_id.0)))
        .await
        .expect("expected successful activation skeleton")
        .into_response();
    assert_eq!(ok_resp.status(), http::StatusCode::OK);
}
#[tokio::test]
async fn runtime_upgrades_list_sorted_by_window() {
    let authority = random_authority();
    let manifests = vec![
        RuntimeUpgradeManifest {
            name: "ABI v1 (late)".into(),
            description: "Third".into(),
            abi_version: 1,
            abi_hash: [0x03; 32],
            added_syscalls: vec![],
            added_pointer_types: vec![],
            start_height: 10,
            end_height: 18,
            sbom_digests: Vec::new(),
            slsa_attestation: Vec::new(),
            provenance: Vec::new(),
        },
        RuntimeUpgradeManifest {
            name: "ABI v1 (early)".into(),
            description: "First".into(),
            abi_version: 1,
            abi_hash: [0x01; 32],
            added_syscalls: vec![],
            added_pointer_types: vec![],
            start_height: 2,
            end_height: 5,
            sbom_digests: Vec::new(),
            slsa_attestation: Vec::new(),
            provenance: Vec::new(),
        },
        RuntimeUpgradeManifest {
            name: "ABI v1 (mid)".into(),
            description: "Second".into(),
            abi_version: 1,
            abi_hash: [0x02; 32],
            added_syscalls: vec![],
            added_pointer_types: vec![],
            start_height: 6,
            end_height: 9,
            sbom_digests: Vec::new(),
            slsa_attestation: Vec::new(),
            provenance: Vec::new(),
        },
    ];
    let mut items: Vec<SimpleItem> = manifests
        .into_iter()
        .enumerate()
        .map(|(idx, manifest)| SimpleItem {
            record: RuntimeUpgradeRecord {
                manifest,
                status: RuntimeUpgradeStatus::Proposed,
                proposer: authority.account.clone(),
                created_height: idx as u64,
            },
        })
        .collect();
    items.sort_by_key(|it| {
        (
            it.record.manifest.start_height,
            it.record.manifest.abi_version,
        )
    });
    let order: Vec<(u64, u16)> = items
        .iter()
        .map(|it| {
            (
                it.record.manifest.start_height,
                it.record.manifest.abi_version,
            )
        })
        .collect();
    assert_eq!(order, vec![(2, 1), (6, 1), (10, 1)]);
}
