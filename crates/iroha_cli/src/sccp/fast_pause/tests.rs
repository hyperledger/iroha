//! Command grammar and exact chain/panel/head binding of public pause intents.

use super::*;
use clap::Parser as _;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn fixture() -> (SccpFastPauseViewV1, EndorseSccpFastPauseV1) {
    let drawn: Vec<_> = (1..=10).map(account).collect();
    let view = SccpFastPauseViewV1 {
        panel: Some(SccpPausePanelV1 {
            panel_seq: 4,
            pulse_id: [1; 32],
            seated_height: 10,
            seated_at_ms: 100,
            accept_until_ms: 200,
            term_ends_at_ms: 1_000,
            accepted: std::collections::BTreeSet::default(),
            primary_id: [2; 32],
            backup_id: [3; 32],
            drawn: drawn.clone(),
        }),
        seats: Some(SccpPauseSeatsV1 {
            primary: drawn[..5].to_vec(),
            backup: drawn[5..].to_vec(),
        }),
        eligibility_available: true,
        rounds: vec![],
        active: vec![],
        suspended: vec![],
    };
    let instruction = EndorseSccpFastPauseV1 {
        network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"chain",
        ))),
        network: SccpNetworkV1::EthereumMainnet,
        panel_id: [2; 32],
        head: 7,
        incident_digest: [4; 32],
    };
    (view, instruction)
}

#[test]
fn acceptance_binds_the_original_draw_and_does_not_invent_eligibility() {
    let (mut view, _) = fixture();
    view.eligibility_available = false;
    view.seats = None;
    assert_eq!(acceptance(&view, &account(1), 4).unwrap().panel_seq, 4);
    assert!(acceptance(&view, &account(1), 3).is_err());
    assert!(acceptance(&view, &account(11), 4).is_err());
    view.panel.as_mut().unwrap().accepted.insert(account(1));
    assert!(acceptance(&view, &account(1), 4).is_err());
    view.panel = None;
    assert!(acceptance(&view, &account(1), 4).is_err());
}

#[test]
fn endorsement_preserves_selected_chain_panel_head_and_incident() {
    let (mut view, intent) = fixture();
    let revisions = [(SccpGovernanceSubjectV1::FastHold(intent.network), 7).into()];
    assert_eq!(
        endorsement(&view, &revisions, &account(1), intent).unwrap(),
        intent
    );
    assert!(endorsement(&view, &revisions, &account(6), intent).is_err());
    for changed in [
        EndorseSccpFastPauseV1 {
            panel_id: [9; 32],
            ..intent
        },
        EndorseSccpFastPauseV1 { head: 6, ..intent },
        EndorseSccpFastPauseV1 {
            incident_digest: [0; 32],
            ..intent
        },
        EndorseSccpFastPauseV1 {
            network: SccpNetworkV1::SoraTaira,
            ..intent
        },
    ] {
        assert!(endorsement(&view, &revisions, &account(1), changed).is_err());
    }
    view.eligibility_available = false;
    assert!(endorsement(&view, &revisions, &account(1), intent).is_err());
    view.eligibility_available = true;
    view.seats = None;
    assert!(endorsement(&view, &revisions, &account(1), intent).is_err());
}

#[test]
fn command_grammar_requires_explicit_replay_bindings() {
    #[derive(clap::Parser)]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }
    assert!(matches!(
        Cli::try_parse_from(["fast-pause", "panel"])
            .unwrap()
            .command,
        Command::Panel
    ));
    assert!(matches!(
        Cli::try_parse_from(["fast-pause", "status"])
            .unwrap()
            .command,
        Command::Status
    ));
    assert!(matches!(
        Cli::try_parse_from(["fast-pause", "accept", "--panel-seq", "4"])
            .unwrap()
            .command,
        Command::Accept(_)
    ));
    assert!(Cli::try_parse_from(["fast-pause", "accept", "--panel-seq", "0"]).is_err());
    assert!(Cli::try_parse_from(["fast-pause", "accept"]).is_err());
    let word = hex::encode([3; 32]);
    let args = [
        "fast-pause",
        "endorse",
        "--network",
        "ethereum-mainnet",
        "--panel-id",
        &word,
        "--head",
        "0",
        "--incident-digest",
        &word,
    ];
    assert!(matches!(
        Cli::try_parse_from(args).unwrap().command,
        Command::Endorse(_)
    ));
    assert!(Cli::try_parse_from(&args[..8]).is_err());
}
