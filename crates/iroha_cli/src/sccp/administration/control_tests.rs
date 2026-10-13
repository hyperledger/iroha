//! Exact retained-target binding for control confirmation after journal reselection.

use super::*;
use iroha_sccp::api::{SccpBlockRefV1, SccpCertificateV1, SccpControlProofBundleV1};
use iroha_sccp_wallet::{
    flow::{SccpFlowActionV1 as Action, SccpFlowV1, drive_step_with_rebroadcast},
    journal::{
        SccpEvidenceItemV1, SccpFlowIdV1, SccpFlowKindV1, SccpJournalOutcomeV1, SccpJournalRoot,
        SccpStepOutcomeKindV1,
    },
};

fn control(nonce: u64) -> SccpEvidenceItemV1 {
    // Only extraction from previously prepared custody is under test here. Native certificate
    // authentication occurs before preparation and has independent genuine-proof coverage.
    super::super::flows::evidence(
        "taira.verified_control",
        &SccpControlProofBundleV1 {
            network: SccpNetworkV1::TonMainnet,
            revision: 2,
            control_nonce: nonce,
            track: 1,
            parliament_paused: false,
            fast_pause_until_ms: 0,
            certificate_id: [1; 32],
            effect_hash: [2; 32],
            leaf_index: 0,
            path: Vec::new(),
            block: SccpBlockRefV1 {
                height: 1,
                sccp_root: [3; 32],
                message_count: 1,
                history_index: 0,
                history_path: Vec::new(),
            },
            certificate: SccpCertificateV1 {
                height: 1,
                qc: [0; 116],
                aggregate_signature: [0; 96],
                header: [0; 221],
                committee: Vec::new(),
            },
        },
    )
    .unwrap()
}

fn workspace_temp() -> tempfile::TempDir {
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sccp-continuation");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new()
        .prefix("control-selection-")
        .tempdir_in(base)
        .unwrap()
}

fn network_id() -> iroha_data_model::NetworkId {
    iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::prehashed([12; 32]),
    ))
}

#[test]
fn control_observer_uses_reselected_step_target_and_preserves_it_after_reopen() {
    let dir = workspace_temp();
    let network = network_id();
    let id = SccpFlowIdV1 {
        kind: SccpFlowKindV1::ControlApply,
        id: [11; 32],
    };
    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network).unwrap().flow(&id).unwrap(),
        *network.as_bytes(),
    )
    .unwrap();
    let first = flow
        .prepare(
            Action::Control,
            SccpNetworkV1::TonMainnet,
            vec![1],
            vec![control(3)],
        )
        .unwrap();
    let captured_target = retained_control_nonce(&first, SccpNetworkV1::TonMainnet, 2).unwrap();
    first.begin_submission().unwrap();
    first
        .complete(&SccpJournalOutcomeV1 {
            outcome: SccpStepOutcomeKindV1::Confirmed,
            transaction: vec![1; 32],
            evidence: vec![control(3)],
        })
        .unwrap();
    drop(first);
    let next = flow
        .prepare(
            Action::Control,
            SccpNetworkV1::TonMainnet,
            vec![2],
            vec![control(5)],
        )
        .unwrap();
    next.begin_submission().unwrap();
    let original = next.record().clone();
    drop(next);

    let applied = 4;
    assert!(applied >= captured_target);
    let selected = flow.latest(Action::Control).unwrap().unwrap();
    let outcome = drive_step_with_rebroadcast::<eyre::Report>(
        &selected,
        false,
        |_| {
            let target = retained_control_nonce(&selected, SccpNetworkV1::TonMainnet, 2)?;
            Ok((applied >= target).then(|| SccpJournalOutcomeV1 {
                outcome: SccpStepOutcomeKindV1::Confirmed,
                transaction: vec![2; 32],
                evidence: vec![control(applied)],
            }))
        },
        |_| panic!("reselection cannot sign or dispatch a replacement"),
    )
    .unwrap();
    assert!(outcome.is_none());
    drop(selected);
    drop(flow);
    drop(root);

    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network).unwrap().flow(&id).unwrap(),
        *network.as_bytes(),
    )
    .unwrap();
    let pending = flow.pending().unwrap().unwrap();
    assert_eq!(pending.record(), &original);
    assert!(pending.outcome().unwrap().is_none());
    assert!(pending.submission_recorded().unwrap());
}

#[test]
fn retained_control_target_requires_unique_positive_nonce_and_exact_deployment() {
    let network = network_id();
    for items in [
        vec![control(0)],
        vec![control(3), control(3)],
        vec![SccpEvidenceItemV1 {
            label: "unrelated".into(),
            bytes: vec![1],
        }],
    ] {
        let dir = workspace_temp();
        let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
        let flow = SccpFlowV1::open(
            root.network(&network)
                .unwrap()
                .flow(&SccpFlowIdV1 {
                    kind: SccpFlowKindV1::ControlApply,
                    id: [11; 32],
                })
                .unwrap(),
            *network.as_bytes(),
        )
        .unwrap();
        let step = flow
            .prepare(Action::Control, SccpNetworkV1::TonMainnet, vec![1], items)
            .unwrap();
        assert!(retained_control_nonce(&step, SccpNetworkV1::TonMainnet, 2).is_err());
    }
    let dir = workspace_temp();
    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network)
            .unwrap()
            .flow(&SccpFlowIdV1 {
                kind: SccpFlowKindV1::ControlApply,
                id: [11; 32],
            })
            .unwrap(),
        *network.as_bytes(),
    )
    .unwrap();
    let step = flow
        .prepare(
            Action::Control,
            SccpNetworkV1::TonMainnet,
            vec![1],
            vec![control(3)],
        )
        .unwrap();
    assert_eq!(
        retained_control_nonce(&step, SccpNetworkV1::TonMainnet, 2).unwrap(),
        3
    );
    assert!(retained_control_nonce(&step, SccpNetworkV1::EthereumMainnet, 2).is_err());
    assert!(retained_control_nonce(&step, SccpNetworkV1::TonMainnet, 3).is_err());
}
