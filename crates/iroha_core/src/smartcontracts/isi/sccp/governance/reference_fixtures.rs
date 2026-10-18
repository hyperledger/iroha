//! Independent Rust producer of governance_v1.json using canonical codecs and Core heads.

#[path = "../../../../../../iroha_sccp/tests/reference_support/python_json.rs"]
mod python_json;

use super::*;
use crate::smartcontracts::isi::sccp::test_support::{blank_state, header};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    governance::types::parliament_expected_head_root_v1,
    sccp::governance::{
        SccpFreezeLightClientActionV1, SccpGovernanceStaticError, SccpSetDestinationPausedActionV1,
        SccpSetFastPauseSuspendedActionV1, SccpSetTairaPausedActionV1,
    },
};
use iroha_sccp::v1::hashes::to_hex;
use norito::{codec::Encode, json, json::Value};

type Subject = SccpGovernanceSubjectV1;
type Action = SccpGovernanceActionV1;

const GENERATOR: &str = "scripts/sccp_reference/vectors_governance.py and crates/iroha_core/src/smartcontracts/isi/sccp/governance/reference_fixtures.rs";
const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const BSC: SccpNetworkV1 = SccpNetworkV1::BscMainnet;
const TON: SccpNetworkV1 = SccpNetworkV1::TonMainnet;

fn hx(bytes: &[u8]) -> String {
    format!("0x{}", to_hex(bytes))
}

fn subject_json(subject: Subject) -> Value {
    let (kind, network) = match subject {
        Subject::Route(n) => ("route", Some(n)),
        Subject::RouteControl(n) => ("route_control", Some(n)),
        Subject::LightClient(n) => ("light_client", Some(n)),
        Subject::Parameters => ("parameters", None),
        Subject::ForgeryHold(n) => ("forgery_hold", Some(n)),
        Subject::FastHold(n) => ("fast_hold", Some(n)),
        Subject::FastPauseControl(n) => ("fast_pause_control", Some(n)),
    };
    let network = network.map(|n| match n {
        ETH => "ethereum-mainnet",
        BSC => "bsc-mainnet",
        TON => "ton-mainnet",
        _ => panic!("external fixture network"),
    });
    json!({"kind": kind, "network": network})
}

fn revisions_json(revisions: &[(Subject, u64)]) -> Value {
    Value::Array(
        revisions
            .iter()
            .map(|(s, r)| json!({"subject": (subject_json(*s)), "revision": r}))
            .collect(),
    )
}

fn action_json(action: &Action) -> Value {
    let network = match action.network().expect("network") {
        ETH => "ethereum-mainnet",
        BSC => "bsc-mainnet",
        TON => "ton-mainnet",
        _ => unreachable!(),
    };
    match action {
        Action::SetTairaPaused(a) => {
            json!({"kind": "set_taira_paused", "network": network, "paused": (a.paused)})
        }
        Action::SetDestinationPaused(a) => {
            json!({"kind": "set_destination_paused", "network": network, "revision": (a.revision), "paused": (a.paused)})
        }
        Action::FreezeLightClient(_) => json!({"kind": "freeze_light_client", "network": network}),
        Action::QuarantineSccpRevision(a) => {
            json!({"kind": "quarantine_revision", "network": network, "revision": (a.revision)})
        }
        Action::SetFastPauseSuspended(a) => {
            json!({"kind": "set_fast_pause_suspended", "network": network, "duration_ms": (a.duration_ms)})
        }
        _ => panic!("unhandled fixture action"),
    }
}

fn row(
    label: &str,
    actions: Vec<Action>,
    revisions: &[(Subject, u64)],
    stale: bool,
    extra_fast_hold: bool,
) -> Value {
    let network_id =
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::prehashed([0x11; 32])));
    let state = blank_state();
    let header = header(1);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    for (subject, revision) in revisions {
        store::set_governance_revision(&mut tx, *subject, *revision);
    }
    let mut proposal = SccpGovernanceProposalV1 {
        network_id,
        base_revisions: vec![],
        actions,
    };
    proposal.base_revisions = proposal
        .subjects()
        .into_iter()
        .map(|s| (s, store::governance_revision(&*tx.world, &s)).into())
        .collect();
    if stale {
        proposal.base_revisions[0].revision += 1;
    }
    if extra_fast_hold {
        proposal
            .base_revisions
            .push((Subject::FastHold(ETH), 0).into());
        proposal.base_revisions.sort_by_key(|r| r.subject);
    }
    let static_outcome = match proposal.validate_static(&network_id) {
        Ok(()) => "Accepted",
        Err(SccpGovernanceStaticError::BaseRevisionsMismatch) => "BaseRevisionsMismatch",
        Err(SccpGovernanceStaticError::ExceedsJsonSafeInteger { .. }) => "ExceedsJsonSafeInteger",
        other => panic!("unexpected static result {other:?}"),
    };
    let attempt_outcome = if static_outcome != "Accepted" {
        "NotAttempted"
    } else {
        match preflight_rejection_in(&*tx.world, &proposal) {
            None => {
                preflight_attempt(&tx, &proposal).expect("attempt");
                "Accepted"
            }
            Some(PreflightRejection::Stale { .. }) => {
                assert!(preflight_attempt(&tx, &proposal).is_err());
                "Stale"
            }
            other => panic!("unexpected preflight result {other:?}"),
        }
    };
    let kind = ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
        proposal: Box::new(proposal.clone()),
    });
    let head = match subject_heads(&*tx.world, &proposal) {
        Ok((version, heads)) => json!({
            "outcome": "Present", "subject_id": (hx(&kind.governed_subject_id_v1().expect("subject"))),
            "version": version, "heads": (revisions_json(&heads)),
            "head_root": (hx(&parliament_expected_head_root_v1(&heads))),
        }),
        Err(error) => {
            assert!(error.to_string().contains("overflows"));
            json!({"outcome": "VersionOverflow"})
        }
    };
    let frame = norito::to_bytes(&proposal).expect("proposal frame");
    let decoded: SccpGovernanceProposalV1 =
        norito::decode_from_bytes(&frame).expect("canonical frame roundtrip");
    assert_eq!(decoded, proposal);
    json!({
        "label": label,
        "input": {
            "network_id": (hx(network_id.as_bytes())),
            "actions": (proposal.actions.iter().map(action_json).collect::<Vec<_>>()),
            "base_revisions": (revisions_json(&proposal.base_revisions.iter().map(|r| (r.subject, r.revision)).collect::<Vec<_>>())),
            "revision_map": (revisions_json(revisions)),
        },
        "expected": {
            "frame": (hx(&frame)), "proposal_id": (hx(&kind.fingerprint())), "effect_hash": (hx(&kind.effect_preimage_hash_v1())),
            "subjects": (proposal.subjects().into_iter().map(subject_json).collect::<Vec<_>>()),
            "head": head, "static_outcome": static_outcome, "attempt_outcome": attempt_outcome,
        },
    })
}

fn build() -> Value {
    let mut subjects = Vec::new();
    for constructor in [Subject::Route, Subject::RouteControl, Subject::LightClient] {
        subjects.extend([ETH, BSC, TON].map(constructor));
    }
    subjects.push(Subject::Parameters);
    for constructor in [
        Subject::ForgeryHold,
        Subject::FastHold,
        Subject::FastPauseControl,
    ] {
        subjects.extend([ETH, BSC, TON].map(constructor));
    }
    let revisions: Vec<_> = subjects
        .iter()
        .enumerate()
        .map(|(i, s)| (*s, i as u64 + 1))
        .collect();
    let pause = Action::SetTairaPaused(SccpSetTairaPausedActionV1 {
        network: ETH,
        paused: true,
    });
    let resume = Action::SetTairaPaused(SccpSetTairaPausedActionV1 {
        network: ETH,
        paused: false,
    });
    let control = Action::SetDestinationPaused(SccpSetDestinationPausedActionV1 {
        network: ETH,
        revision: 1,
        paused: false,
    });
    let hold = Action::QuarantineSccpRevision(SccpRouteRevisionActionV1 {
        network: BSC,
        revision: 2,
    });
    let suspend = Action::SetFastPauseSuspended(SccpSetFastPauseSuspendedActionV1 {
        network: TON,
        duration_ms: 60_000,
    });
    let freeze = Action::FreezeLightClient(SccpFreezeLightClientActionV1 { network: BSC });
    let rows = vec![
        row("absent_route_head", vec![pause.clone()], &[], false, false),
        row(
            "fixed_route_head",
            vec![pause.clone()],
            &revisions,
            false,
            false,
        ),
        row(
            "different_effect_same_subject",
            vec![resume],
            &revisions,
            false,
            false,
        ),
        row(
            "control_head",
            vec![control.clone()],
            &revisions,
            false,
            false,
        ),
        row(
            "forgery_hold_head",
            vec![hold.clone()],
            &revisions,
            false,
            false,
        ),
        row(
            "fast_pause_control_head",
            vec![suspend.clone()],
            &revisions,
            false,
            false,
        ),
        row(
            "sorted_deduplicated_subjects",
            vec![suspend, control, hold, pause.clone(), freeze, pause.clone()],
            &revisions,
            false,
            false,
        ),
        row(
            "stale_base_revision",
            vec![pause.clone()],
            &revisions,
            true,
            false,
        ),
        row(
            "fast_hold_is_not_a_parliament_action",
            vec![pause.clone()],
            &revisions,
            false,
            true,
        ),
        row(
            "head_version_overflow",
            vec![pause],
            &[(Subject::Route(ETH), u64::MAX)],
            false,
            false,
        ),
    ];
    // Automatic FastHold participates in revision storage even though no Parliament
    // action may govern it. Exercise the same head reader on this complete state view.
    let state = blank_state();
    let header = header(1);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    for (subject, revision) in &revisions {
        store::set_governance_revision(&mut tx, *subject, *revision);
    }
    let (snapshot_version, snapshot_heads) =
        heads_for_subjects(&*tx.world, subjects.iter().copied()).expect("all subject heads");
    json!({
        "schema": "iroha.sccp.governance.v1", "generator": GENERATOR,
        "conventions": {
            "encoding": "Norito v1, uncompressed, COMPACT_LEN field lengths, flags 2; hex is 0x-prefixed.",
            "authority": "Proposal/head computation does not authenticate a ballot or enact an effect. Both launch gates remain false.",
            "fast_hold": "FastHold is automatic state; it has head snapshots but no Parliament action. An extra FastHold base revision is refused.",
        },
        "constants": {"network_id": (hx(&[0x11; 32])), "revision_map": (revisions_json(&revisions))},
        "subject_encodings": (subjects.iter().map(|s| json!({"subject": (subject_json(*s)), "bytes": (hx(&s.encode()))})).collect::<Vec<_>>()),
        "head_snapshots": [{"label": "all_subjects_including_automatic_fast_hold", "subjects": (subjects.into_iter().map(subject_json).collect::<Vec<_>>()),
            "expected": {"outcome": "Present", "version": snapshot_version,
                "heads": (revisions_json(&snapshot_heads)), "head_root": (hx(&parliament_expected_head_root_v1(&snapshot_heads)))}}],
        "rows": rows,
    })
}

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sccp/governance_v1.json")
}

#[test]
fn reference_governance_v1_matches_committed_fixture() {
    let generated = build();
    let actual = std::fs::read_to_string(fixture_path()).expect("governance fixture");
    let parsed: Value = norito::json::from_str(&actual).expect("fixture JSON");
    assert_eq!(python_json::first_difference(&generated, &parsed), None);
    assert_eq!(
        python_json::render(&generated),
        actual,
        "byte-for-byte governance drift"
    );
}

#[test]
#[ignore = "rewrites governance_v1.json after a reviewed fixture change"]
fn regenerate_governance_v1() {
    std::fs::write(fixture_path(), python_json::render(&build()))
        .expect("write governance fixture");
}
