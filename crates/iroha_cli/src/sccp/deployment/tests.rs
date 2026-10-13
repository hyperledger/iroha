//! Retained deployment pins bind both live observations and cached-result output.

use super::*;
use iroha::data_model::sccp::deployment::SccpCommitteePinV1;
use iroha_sccp_wallet::{
    flow::{SccpFlowV1, drive_step_with_rebroadcast},
    journal::{
        SccpEvidenceItemV1, SccpFlowIdV1, SccpJournalOutcomeV1, SccpJournalRoot,
        SccpStepOutcomeKindV1,
    },
};

fn pin(generation: u64) -> SccpCommitteePinV1 {
    SccpCommitteePinV1 {
        generation,
        committee_root: [1; 32],
        start_height: generation * 10,
        until_ms: generation * 1000,
    }
}

fn workspace_temp() -> tempfile::TempDir {
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sccp-continuation");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new()
        .prefix("deployment-selection-")
        .tempdir_in(base)
        .unwrap()
}

fn network_id() -> iroha_data_model::NetworkId {
    iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::prehashed([12; 32]),
    ))
}

#[test]
fn concurrent_first_deployment_refuses_a_different_selected_generation_without_replacement() {
    for chain in [SccpNetworkV1::TonMainnet, SccpNetworkV1::EthereumMainnet] {
        let dir = workspace_temp();
        let network = network_id();
        let id = SccpFlowIdV1 {
            kind: Kind::Deployment,
            id: [11; 32],
        };
        let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
        let flow = SccpFlowV1::open(
            root.network(&network).unwrap().flow(&id).unwrap(),
            *network.as_bytes(),
        )
        .unwrap();
        assert!(flow.latest(Action::Deploy).unwrap().is_none());
        let computed_a = pin(3);
        // Another invocation resolves a later generation and prepares first under the same
        // semantic "latest generation" intent before this invocation reacquires the step.
        let computed_b = pin(4);
        let selected = flow
            .prepare(
                Action::Deploy,
                chain,
                vec![9, 8, 7],
                vec![flows::evidence("deployment.committee_pin", &computed_b).unwrap()],
            )
            .unwrap();
        selected.begin_submission().unwrap();
        let original = selected.record().clone();
        drop(selected);
        let selected = flow.latest(Action::Deploy).unwrap().unwrap();
        assert_eq!(step_pin(&selected).unwrap(), computed_b);
        let result = drive_step_with_rebroadcast::<eyre::Report>(
            &selected,
            false,
            |_| {
                require_step_pin(&selected, &computed_a)?;
                panic!("a different minter or runtime cannot be observed for this step")
            },
            |_| panic!("pin mismatch cannot sign or dispatch a replacement"),
        );
        assert!(result.is_err());
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
        require_step_pin(&pending, &computed_b).unwrap();
        pending
            .complete(&SccpJournalOutcomeV1 {
                outcome: SccpStepOutcomeKindV1::Confirmed,
                transaction: vec![5; 32],
                evidence: vec![flows::evidence("deployment.committee_pin", &computed_b).unwrap()],
            })
            .unwrap();
        drop(pending);

        // A cached outcome skips the observer. The same exact-step guard used before printing
        // the registration action still refuses A's address/runtime and original generation.
        let completed = flow.latest(Action::Deploy).unwrap().unwrap();
        assert!(completed.outcome().unwrap().is_some());
        assert!(require_step_pin(&completed, &computed_a).is_err());
        require_step_pin(&completed, &computed_b).unwrap();
    }
}

#[test]
fn deployment_pin_requires_unique_custody_and_all_original_coordinates() {
    let network = network_id();
    let item = flows::evidence("deployment.committee_pin", &pin(3)).unwrap();
    for items in [
        vec![item.clone(), item.clone()],
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
                    kind: Kind::Deployment,
                    id: [11; 32],
                })
                .unwrap(),
            *network.as_bytes(),
        )
        .unwrap();
        let step = flow
            .prepare(Action::Deploy, SccpNetworkV1::TonMainnet, vec![1], items)
            .unwrap();
        assert!(step_pin(&step).is_err());
    }
    let dir = workspace_temp();
    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network)
            .unwrap()
            .flow(&SccpFlowIdV1 {
                kind: Kind::Deployment,
                id: [11; 32],
            })
            .unwrap(),
        *network.as_bytes(),
    )
    .unwrap();
    let step = flow
        .prepare(
            Action::Deploy,
            SccpNetworkV1::TonMainnet,
            vec![1],
            vec![item],
        )
        .unwrap();
    for altered in [
        SccpCommitteePinV1 {
            committee_root: [2; 32],
            ..pin(3)
        },
        SccpCommitteePinV1 {
            start_height: 31,
            ..pin(3)
        },
        SccpCommitteePinV1 {
            until_ms: 3001,
            ..pin(3)
        },
    ] {
        assert!(require_step_pin(&step, &altered).is_err());
    }
    require_step_pin(&step, &pin(3)).unwrap();
}
