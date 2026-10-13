//! Original-byte dispatch, failure and restart regression tests.

use super::*;
use crate::journal::SccpJournalRoot;
use iroha_data_model::NetworkId;
use std::{cell::Cell, path::Path};

fn root() -> tempfile::TempDir {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sccp-continuation");
    std::fs::create_dir_all(&path).unwrap();
    tempfile::Builder::new()
        .prefix("wallet-flow-")
        .tempdir_in(path)
        .unwrap()
}

fn open(path: &Path, kind: SccpFlowKindV1) -> SccpFlowV1 {
    let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::prehashed([7; 32]),
    ));
    let journal = SccpJournalRoot::open(&path.join("journal"))
        .unwrap()
        .network(&network)
        .unwrap()
        .flow(&SccpFlowIdV1 { kind, id: [3; 32] })
        .unwrap();
    SccpFlowV1::open(journal, *network.as_bytes()).unwrap()
}

fn evidence() -> Vec<SccpEvidenceItemV1> {
    vec![SccpEvidenceItemV1 {
        label: "verified.original".to_owned(),
        bytes: vec![1, 2, 3],
    }]
}

#[test]
fn deployment_retains_original_pin_and_cannot_repeat_after_confirmed_effect() {
    let root = root();
    let flow = open(root.path(), SccpFlowKindV1::Deployment);
    assert!(
        flow.prepare(
            SccpFlowActionV1::Deploy,
            SccpNetworkV1::SoraTaira,
            vec![1],
            evidence()
        )
        .is_err()
    );
    let step = flow
        .prepare(
            SccpFlowActionV1::Deploy,
            SccpNetworkV1::TonMainnet,
            vec![3, 7],
            evidence(),
        )
        .unwrap();
    assert!(step.begin_submission().unwrap());
    drop(step);
    drop(flow);
    let flow = open(root.path(), SccpFlowKindV1::Deployment);
    let step = flow.latest(SccpFlowActionV1::Deploy).unwrap().unwrap();
    assert_eq!(step.record().submission, [3, 7]);
    assert_eq!(step.record().evidence, evidence());
    assert!(!step.begin_submission().unwrap());
    drive_step::<JournalError>(
        &step,
        |_| Ok(Some(outcome(SccpStepOutcomeKindV1::Confirmed))),
        |_| panic!("already deployed"),
    )
    .unwrap();
    drop(step);
    assert_eq!(flow.phase().unwrap(), SccpFlowPhaseV1::Complete);
    assert!(
        flow.prepare(
            SccpFlowActionV1::Deploy,
            SccpNetworkV1::TonMainnet,
            vec![3, 8],
            evidence()
        )
        .is_err()
    );
}

fn outcome(kind: SccpStepOutcomeKindV1) -> SccpJournalOutcomeV1 {
    SccpJournalOutcomeV1 {
        outcome: kind,
        transaction: vec![8; 32],
        evidence: evidence(),
    }
}

#[test]
fn loss_after_dispatch_retains_original_and_restart_never_resubmits() {
    let root = root();
    let flow = open(root.path(), SccpFlowKindV1::Outbound);
    let step = flow
        .prepare(
            SccpFlowActionV1::Finalize,
            SccpNetworkV1::EthereumMainnet,
            vec![0x02, 9],
            evidence(),
        )
        .unwrap();
    let called = Cell::new(0);
    let result = drive_step::<JournalError>(
        &step,
        |_| Ok(None),
        |bytes| {
            assert_eq!(bytes, [0x02, 9]);
            assert_eq!(step.record().submission, bytes);
            assert!(step.submission_recorded().unwrap());
            assert!(!step.record().evidence.is_empty());
            called.set(called.get() + 1);
            Err(invalid("response lost after acceptance"))
        },
    );
    assert!(result.is_err());
    drop(step);
    drop(flow);
    let reopened = open(root.path(), SccpFlowKindV1::Outbound);
    assert!(
        reopened
            .prepare(
                SccpFlowActionV1::Finalize,
                SccpNetworkV1::EthereumMainnet,
                vec![0x02, 10],
                evidence()
            )
            .is_err()
    );
    let original = reopened.pending().unwrap().unwrap();
    assert_eq!(original.record().submission, [0x02, 9]);
    assert!(
        drive_step::<JournalError>(
            &original,
            |_| Ok(None),
            |_| {
                called.set(called.get() + 1);
                Ok(())
            }
        )
        .unwrap()
        .is_none()
    );
    let confirmed = outcome(SccpStepOutcomeKindV1::Confirmed);
    assert_eq!(
        drive_step::<JournalError>(
            &original,
            |_| Ok(Some(confirmed.clone())),
            |_| panic!("recovery must be read-only")
        )
        .unwrap(),
        Some(confirmed)
    );
    assert_eq!(called.get(), 1);
    assert_eq!(reopened.phase().unwrap(), SccpFlowPhaseV1::Complete);
    assert!(
        reopened
            .prepare(
                SccpFlowActionV1::Finalize,
                SccpNetworkV1::EthereumMainnet,
                vec![2],
                evidence()
            )
            .is_err()
    );
}

#[test]
fn crash_after_marker_before_dispatch_requires_exact_explicit_rebroadcast() {
    let root = root();
    let flow = open(root.path(), SccpFlowKindV1::Inbound);
    let step = flow
        .prepare(
            SccpFlowActionV1::Burn,
            SccpNetworkV1::TonMainnet,
            vec![0xb5, 0xee],
            evidence(),
        )
        .unwrap();
    assert!(step.begin_submission().unwrap());
    drop(step);
    let step = flow.pending().unwrap().unwrap();
    assert!(
        drive_step::<JournalError>(
            &step,
            |_| Ok(None),
            |_| panic!("marker blocks all redispatch")
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(flow.phase().unwrap(), SccpFlowPhaseV1::Ready);
    let broadcast = Cell::new(false);
    let recovered = drive_step_with_rebroadcast::<JournalError>(
        &step,
        true,
        |_| {
            Ok(broadcast
                .get()
                .then(|| outcome(SccpStepOutcomeKindV1::Confirmed)))
        },
        |bytes| {
            assert_eq!(bytes, [0xb5, 0xee]);
            broadcast.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(recovered.is_some());
    assert!(
        broadcast.get(),
        "explicit recovery sends the original seqno-bound bytes after reconciliation"
    );
    assert_eq!(flow.phase().unwrap(), SccpFlowPhaseV1::AwaitingProof);
}

#[test]
fn prepared_restart_dispatches_once_and_refused_chain_never_writes() {
    let root = root();
    let flow = open(root.path(), SccpFlowKindV1::Refund);
    assert!(
        flow.prepare(
            SccpFlowActionV1::ProveVoid,
            SccpNetworkV1::EthereumMainnet,
            vec![1],
            evidence()
        )
        .is_err()
    );
    assert!(
        flow.prepare(
            SccpFlowActionV1::Burn,
            SccpNetworkV1::TonMainnet,
            vec![1],
            evidence()
        )
        .is_err()
    );
    assert!(flow.pending().unwrap().is_none());
    drop(
        flow.prepare(
            SccpFlowActionV1::ProveVoid,
            SccpNetworkV1::SoraTaira,
            vec![1, 2],
            evidence(),
        )
        .unwrap(),
    );
    let step = flow.pending().unwrap().unwrap();
    let sent = Cell::new(false);
    drive_step::<JournalError>(
        &step,
        |_| {
            Ok(sent
                .get()
                .then(|| outcome(SccpStepOutcomeKindV1::Confirmed)))
        },
        |bytes| {
            assert_eq!(bytes, [1, 2]);
            sent.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(flow.phase().unwrap(), SccpFlowPhaseV1::AwaitingSettlement);
    drop(step);
    let finish = flow
        .prepare(
            SccpFlowActionV1::ObserveComplete,
            SccpNetworkV1::SoraTaira,
            vec![],
            evidence(),
        )
        .unwrap();
    drive_step::<JournalError>(
        &finish,
        |_| Ok(Some(outcome(SccpStepOutcomeKindV1::Confirmed))),
        |_| panic!("observation sends nothing"),
    )
    .unwrap();
    assert_eq!(flow.phase().unwrap(), SccpFlowPhaseV1::Complete);
}

#[test]
fn failed_effect_allows_new_attempt_only_after_durable_evidence() {
    let root = root();
    let flow = open(root.path(), SccpFlowKindV1::Outbound);
    let step = flow
        .prepare(
            SccpFlowActionV1::Finalize,
            SccpNetworkV1::BscMainnet,
            vec![1],
            evidence(),
        )
        .unwrap();
    let invalid_outcome = SccpJournalOutcomeV1 {
        evidence: vec![],
        ..outcome(SccpStepOutcomeKindV1::Failed)
    };
    assert!(
        drive_step::<JournalError>(
            &step,
            |_| Ok(Some(invalid_outcome.clone())),
            |_| panic!("invalid outcome")
        )
        .is_err()
    );
    assert!(step.outcome().unwrap().is_none());
    drive_step::<JournalError>(
        &step,
        |_| Ok(Some(outcome(SccpStepOutcomeKindV1::Failed))),
        |_| panic!("already failed"),
    )
    .unwrap();
    drop(step);
    let next = flow
        .prepare(
            SccpFlowActionV1::Finalize,
            SccpNetworkV1::BscMainnet,
            vec![2],
            evidence(),
        )
        .unwrap();
    assert_eq!(next.record().step, 1);
    assert_eq!(flow.phase().unwrap(), SccpFlowPhaseV1::Ready);
    let wire = norito::json::to_vec(next.record()).unwrap();
    assert_eq!(
        norito::json::from_slice::<SccpJournalRecordV1>(&wire).unwrap(),
        *next.record()
    );
    assert!(norito::json::from_str::<SccpFlowActionV1>("{\"action\":\"Unknown\"}").is_err());
}

#[test]
fn evidence_recovery_finds_original_before_changed_source_recheck() {
    let root = root();
    let flow = open(root.path(), SccpFlowKindV1::EvidenceSubmission);
    let digest = [4; 32];
    let mut items = evidence();
    items.push(SccpEvidenceItemV1 {
        label: "sccp.intent.sha256".to_owned(),
        bytes: digest.to_vec(),
    });
    let step = flow
        .prepare(
            SccpFlowActionV1::RecordEvidence,
            SccpNetworkV1::SoraTaira,
            vec![1, 7, 9],
            items,
        )
        .unwrap();
    let original = step.record().clone();
    drop(step);
    assert!(
        flow.find_intent(SccpFlowActionV1::RecordEvidence, &[5; 32])
            .unwrap()
            .is_none()
    );
    assert_eq!(
        flow.find_intent(SccpFlowActionV1::RecordEvidence, &digest)
            .unwrap()
            .unwrap()
            .record(),
        &original
    );
    let step = flow
        .latest(SccpFlowActionV1::RecordEvidence)
        .unwrap()
        .unwrap();
    drive_step::<JournalError>(
        &step,
        |_| Ok(Some(outcome(SccpStepOutcomeKindV1::Confirmed))),
        |_| panic!("observed original already committed"),
    )
    .unwrap();
    drop(step);
    assert_eq!(flow.phase().unwrap(), SccpFlowPhaseV1::Complete);
    assert_eq!(
        flow.latest(SccpFlowActionV1::RecordEvidence)
            .unwrap()
            .unwrap()
            .record(),
        &original
    );
}
