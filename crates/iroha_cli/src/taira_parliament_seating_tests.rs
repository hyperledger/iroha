//! Parliament seating rules, genesis rendering and the seating command (`specs/sccp.md` §4.14.5).

use super::*;
use clap::Parser as _;
use iroha::data_model::{
    asset::{AssetBalancePolicy, AssetDefinition},
    block::consensus::SumeragiGenesisContextParameters,
    domain::Domain,
    parameter::{Parameter, system::SumeragiNposParameters},
};
use iroha_model_base::{domain::DomainId, peer::PeerId};
use iroha_primitives::numeric::NumericSpec;

const CANONICAL_XOR: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";

fn canonical() -> SeatingProfile {
    SeatingProfile::canonical().expect("canonical Taira seating profile")
}

fn failed(profile: &SeatingProfile, citizens: Option<u64>) -> Vec<&'static str> {
    profile
        .requirements(citizens)
        .into_iter()
        .filter(|requirement| !requirement.ok)
        .map(|requirement| requirement.name)
        .collect()
}

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture key")
            .public_key()
            .clone(),
    )
}

/// A profile built from `gov` assignments plus an enabled 25 000 XOR faucet with `faucet`.
fn profile(gov: &str, faucet: &str) -> SeatingProfile {
    SeatingProfile::from_toml(&format!(
        "[gov]\n{gov}\n[torii.faucet]\nenabled = true\namount = \"25000\"\n{faucet}\n"
    ))
    .expect("fixture profile")
}

const SEATED_GOV: &str = "citizenship_bond_amount = \"1000000\"
rules_committee_size = 5
agenda_council_size = 5
interest_panel_size = 5
review_panel_size = 5
coordination_council_size = 5
mpc_committee_size = 5
fma_committee_size = 5
oversight_committee_size = 5
policy_jury_size = 9
confirmation_jury_size = 7
[gov.parliament_timed_ovn]
max_corpus_entries = 16
registration_phase_blocks = 300
survivor_freeze_phase_blocks = 100";
const ADAPTIVE_FAUCET: &str = "pow_adaptive_lookback_blocks = 64
pow_adaptive_claims_per_extra_bit = 2
pow_adaptive_max_extra_bits = 8";

#[test]
fn canonical_profile_is_the_recommended_taira_profile() {
    let profile = canonical();
    assert!(
        profile.public_bodies.iter().all(|(_, size)| *size == 5),
        "{:?}",
        profile.public_bodies
    );
    assert!(profile.coordination_explicit);
    assert_eq!(profile.policy_jury_size, 9);
    assert_eq!(profile.confirmation_jury_size, 7);
    assert_eq!(profile.max_corpus_entries, 16);
    assert_eq!(profile.registration_phase_blocks, 300);
    assert_eq!(profile.survivor_freeze_phase_blocks, 100);
    assert_eq!(profile.citizenship_bond, Quantity::from(1_000_000_u32));
    assert_eq!(profile.citizenship_asset_id, CANONICAL_XOR);
    let faucet = profile
        .faucet
        .as_ref()
        .expect("canonical faucet is enabled");
    assert_eq!(faucet.amount, Quantity::from(25_000_u32));
    assert!(
        faucet.lookback_blocks > 0 && faucet.claims_per_extra_bit > 0 && faucet.max_extra_bits > 0
    );
    assert_eq!(faucet.difficulty_bits, 4);
    assert_eq!(faucet.max_anchor_age_blocks, 6);
    assert!(faucet.max_anchor_age_blocks < faucet.lookback_blocks);
    // The README and config.toml figures: the cheapest bond-sized burst against flat PoW.
    assert_eq!(faucet.burst_evaluations(40), 81_984);
    assert_eq!(faucet.flat_evaluations(40), 640);
    assert_eq!(profile.largest_required_body(), ("policy_jury_size", 9));
    assert_eq!(profile.minimum_citizens(), 9);
    assert!(failed(&profile, None).is_empty());
    assert!(failed(&profile, Some(u64::from(DEFAULT_GENESIS_CITIZENS))).is_empty());
    // The checked-in escrow is the published sample account; seating always replaces it.
    let error = refuse_unseated(&profile, u64::from(DEFAULT_GENESIS_CITIZENS))
        .unwrap_err()
        .to_string();
    assert!(error.contains("citizenship_escrow_is_custodial"), "{error}");
    assert!(!error.contains("citizens_cover_bodies"), "{error}");
    let seated = with_escrow(
        &profile_table(CANONICAL_TAIRA_PROFILE),
        &fixture_citizenship_escrow(),
    );
    refuse_unseated(&seated, u64::from(DEFAULT_GENESIS_CITIZENS)).expect("sixteen seat Taira");
    let error = refuse_unseated(&seated, 8).unwrap_err().to_string();
    assert!(error.contains("citizens_cover_bodies"), "{error}");
    assert!(error.contains("§4.14.5"), "{error}");
}

fn profile_table(text: &str) -> toml::Table {
    toml::from_str(text).expect("fixture TOML")
}

/// The profile of `config` with its citizenship escrow set to `escrow`.
fn with_escrow(config: &toml::Table, escrow: &AccountId) -> SeatingProfile {
    let mut config = config.clone();
    set_citizenship_escrow(&mut config, escrow).expect("escrow override");
    SeatingProfile::from_config(&config).expect("fixture profile")
}

fn taira_literal(account: &AccountId) -> String {
    let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    account.to_string()
}

#[test]
fn published_accounts_cover_every_key_shipped_in_the_repository() {
    use iroha_test_samples as samples;
    let published = published_accounts();
    for account in [
        samples::ALICE_ID.clone(),
        samples::BOB_ID.clone(),
        samples::CARPENTER_ID.clone(),
        samples::SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        samples::REAL_GENESIS_ACCOUNT_ID.clone(),
        AccountId::new(samples::PEER_KEYPAIR.public_key().clone()),
        iroha_config::parameters::defaults::governance::citizenship_escrow_account_id(),
        iroha_config::parameters::defaults::governance::bond_escrow_account_id(),
        iroha_config::parameters::defaults::governance::slash_receiver_account_id(),
    ] {
        assert!(published.contains(&account), "{account}");
    }
    // Every compiled sample key parses, and the Kagami dev profile keys are scanned.
    for key in PUBLISHED_SAMPLE_PUBLIC_KEYS {
        let key: iroha_crypto::PublicKey = key.parse().expect("canonical sample key");
        assert!(published.contains(&AccountId::new(key)));
    }
    let dev_identity: iroha_crypto::PublicKey =
        "ed0120251E8C5AA2621EBEF90085AF39EE70F24E848B926843D3A65C2BD5E4572AFAB6"
            .parse()
            .unwrap();
    assert!(published.contains(&AccountId::new(dev_identity)));
    assert!(!published.contains(&fixture_citizenship_escrow()));
    assert!(!published.contains(&account(77)));
}

#[test]
fn citizenship_escrow_must_not_be_controlled_by_a_published_key() {
    let base = profile_table(&format!("[gov]\n{SEATED_GOV}\n"));
    let requirement = |profile: &SeatingProfile| profile.citizenship_escrow_requirement();

    let unset = SeatingProfile::from_config(&base).unwrap();
    let verdict = requirement(&unset);
    assert_eq!(verdict.name, "citizenship_escrow_is_custodial");
    assert!(!verdict.ok);
    assert!(verdict.detail.contains("unset"), "{}", verdict.detail);

    for published in [
        iroha_config::parameters::defaults::governance::citizenship_escrow_account_id(),
        iroha_test_samples::BOB_ID.clone(),
    ] {
        let verdict = requirement(&with_escrow(&base, &published));
        assert!(!verdict.ok, "{published}");
        assert!(verdict.detail.contains("published"), "{}", verdict.detail);
        let error = refuse_unseated(&with_escrow(&base, &published), 16)
            .unwrap_err()
            .to_string();
        assert!(error.contains("citizenship_escrow_is_custodial"), "{error}");
    }
    // The canonical config.toml literal is a sample account whose test key is published.
    let checked_in = canonical();
    let sample = checked_in
        .citizenship_escrow()
        .expect("canonical escrow literal parses");
    assert!(published_accounts().contains(&sample), "{sample}");
    assert!(!requirement(&checked_in).ok);

    let fresh = with_escrow(&base, &fixture_citizenship_escrow());
    assert!(requirement(&fresh).ok, "{}", requirement(&fresh).detail);
    assert_eq!(
        fresh.citizenship_escrow(),
        Some(fixture_citizenship_escrow())
    );
    refuse_unseated(&fresh, 16).expect("fresh escrow seats");

    let mut garbage = base.clone();
    garbage
        .get_mut("gov")
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .insert("citizenship_escrow_account".into(), "escrow".into());
    let garbage = SeatingProfile::from_config(&garbage).unwrap();
    assert!(!requirement(&garbage).ok);
    assert!(garbage.citizenship_escrow().is_none());
    let mut malformed = base;
    malformed
        .get_mut("gov")
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .insert("citizenship_escrow_account".into(), toml::Value::Integer(1));
    assert!(SeatingProfile::from_config(&malformed).is_err());
}

#[test]
fn citizenship_escrow_override_writes_the_taira_literal() {
    let escrow = fixture_citizenship_escrow();
    let mut config = toml::Table::new();
    set_citizenship_escrow(&mut config, &escrow).unwrap();
    assert_eq!(
        config["gov"]["citizenship_escrow_account"].as_str(),
        Some(taira_literal(&escrow).as_str())
    );
    let mut replaced: toml::Table = toml::from_str(&format!(
        "[gov]\ncitizenship_escrow_account = \"{}\"\npolicy_jury_size = 9\n",
        taira_literal(
            &iroha_config::parameters::defaults::governance::citizenship_escrow_account_id()
        )
    ))
    .unwrap();
    set_citizenship_escrow(&mut replaced, &escrow).unwrap();
    assert_eq!(
        replaced["gov"]["citizenship_escrow_account"].as_str(),
        Some(taira_literal(&escrow).as_str())
    );
    assert_eq!(replaced["gov"]["policy_jury_size"].as_integer(), Some(9));
    let mut malformed: toml::Table = toml::from_str("gov = 1\n").unwrap();
    assert!(set_citizenship_escrow(&mut malformed, &escrow).is_err());
}

#[test]
fn anchor_age_must_stay_below_the_adaptive_lookback() {
    let failed_names = |faucet: &str| failed(&profile(SEATED_GOV, faucet), Some(16));
    let seated = profile(SEATED_GOV, ADAPTIVE_FAUCET);
    let faucet = seated.faucet.as_ref().unwrap();
    // Unset keys take the iroha_config defaults: 18 base bits and a 6-block anchor age.
    assert_eq!(faucet.difficulty_bits, 18);
    assert_eq!(faucet.max_anchor_age_blocks, 6);
    assert!(failed_names(ADAPTIVE_FAUCET).is_empty());
    // A claimant pinning an anchor older than the lookback is never counted.
    let stale = format!("{ADAPTIVE_FAUCET}\npow_max_anchor_age_blocks = 256");
    assert_eq!(failed_names(&stale), ["faucet_anchor_age_below_lookback"]);
    let detail = profile(SEATED_GOV, &stale)
        .requirements(Some(16))
        .into_iter()
        .find(|requirement| requirement.name == "faucet_anchor_age_below_lookback")
        .unwrap()
        .detail;
    assert!(detail.contains("pow_max_anchor_age_blocks=256"), "{detail}");
    // Below the lookback but at least a bond's claims old: the burst still pays flat PoW.
    let bond_sized = format!("{ADAPTIVE_FAUCET}\npow_max_anchor_age_blocks = 40");
    assert_eq!(
        failed_names(&bond_sized),
        ["faucet_anchor_age_below_lookback"]
    );
    let tight = format!("{ADAPTIVE_FAUCET}\npow_max_anchor_age_blocks = 1");
    assert!(failed_names(&tight).is_empty());
    // With adaptive difficulty off only that requirement fails.
    assert_eq!(
        failed_names("pow_adaptive_lookback_blocks = 64\npow_max_anchor_age_blocks = 256"),
        ["adaptive_faucet_difficulty"]
    );
}

#[test]
fn burst_cost_counts_only_claims_older_than_the_anchor_age() {
    let reach = |age: u64, lookback: u64, per_bit: u64, max_bits: u64| FaucetReach {
        amount: Quantity::from(25_000_u32),
        difficulty_bits: 4,
        max_anchor_age_blocks: age,
        lookback_blocks: lookback,
        claims_per_extra_bit: per_bit,
        max_extra_bits: max_bits,
    };
    assert_eq!(reach(6, 64, 2, 8).burst_evaluations(40), 81_984);
    // Zero anchor age: bits 4 to 11 for the first 16 claims, then 12.
    assert_eq!(reach(0, 64, 2, 8).burst_evaluations(40), 106_464);
    // An anchor age of at least the burst length leaves every claim at the base.
    assert_eq!(reach(256, 64, 2, 8).burst_evaluations(40), 640);
    assert_eq!(reach(40, 64, 2, 8).burst_evaluations(40), 640);
    // Disabled adaptation is flat.
    for disabled in [reach(0, 0, 2, 8), reach(0, 64, 0, 8), reach(0, 64, 2, 0)] {
        assert_eq!(
            disabled.burst_evaluations(40),
            disabled.flat_evaluations(40)
        );
    }
    // The lookback caps the count.
    assert_eq!(
        reach(0, 4, 1, 8).burst_evaluations(6),
        16 + 32 + 64 + 128 + 256 + 256
    );
    assert_eq!(reach(0, 64, 2, 8).flat_evaluations(0), 0);
    // Huge difficulties saturate instead of overflowing.
    let mut huge = reach(0, 64, 2, 8);
    huge.difficulty_bits = 255;
    assert_eq!(huge.burst_evaluations(40), u128::MAX);
    assert_eq!(huge.flat_evaluations(2), u128::MAX);
}

/// The Taira-config parse test: the checked-in `[gov]` table passes every `iroha_config`
/// assertion (corpus covers both juries, windows cover the corpus, anonymity floors).
#[test]
fn canonical_gov_table_parses_through_iroha_config() {
    use iroha_config::{
        base::{env::MockEnv, read::ConfigReader, toml::TomlSource},
        parameters::user,
    };
    // Taira account literals carry the Taira address discriminant.
    let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    let mut document: toml::Table = toml::from_str(CANONICAL_TAIRA_PROFILE).unwrap();
    let gov = document
        .remove("gov")
        .and_then(|gov| gov.as_table().cloned())
        .expect("canonical [gov]");
    let gov = ConfigReader::new()
        .with_env(MockEnv::default())
        .with_toml_source(TomlSource::inline(gov))
        .read_and_complete::<user::Governance>()
        .expect("canonical [gov] reads through the production schema")
        .parse();
    assert_eq!(gov.policy_jury_size, 9);
    assert_eq!(gov.confirmation_jury_size, 7);
    assert_eq!(gov.coordination_council_size, 5);
    assert_eq!(gov.parliament_alternate_size, 3);
    assert_eq!(gov.min_enactment_delay, 50);
    assert_eq!(gov.parliament_invitation_phase_blocks, 300);
    assert_eq!(gov.parliament_public_finding_phase_blocks, 900);
    assert_eq!(gov.parliament_timed_ovn.max_corpus_entries, 16);
    assert_eq!(gov.parliament_timed_ovn.registration_phase_blocks, 300);
    assert_eq!(gov.parliament_timed_ovn.survivor_freeze_phase_blocks, 100);
    assert_eq!(gov.parliament_timed_ovn.commitment_phase_blocks, 300);
    assert_eq!(gov.parliament_timed_ovn.release_delay_blocks, 50);
    assert_eq!(gov.parliament_timed_ovn.opening_phase_blocks, 300);
    assert_eq!(
        gov.parliament_tle_key_lifecycle
            .max_fresh_ballots_per_session,
        8
    );
    assert_eq!(
        gov.parliament_tle_key_lifecycle.session_lifetime_blocks,
        7_200
    );
    assert_eq!(gov.citizenship_bond_amount, Quantity::from(1_000_000_u32));
}

#[test]
fn default_profile_cannot_seat_sixteen_citizens() {
    let profile = SeatingProfile::from_toml("").unwrap();
    assert!(profile.faucet.is_none());
    assert_eq!(
        failed(&profile, Some(16)),
        [
            "citizens_cover_bodies",
            "policy_jury_confirmation_margin",
            "coordination_council_explicit",
        ]
    );
}

#[test]
fn bond_reach_and_adaptive_difficulty_follow_the_faucet() {
    let seated = profile(SEATED_GOV, ADAPTIVE_FAUCET);
    assert!(failed(&seated, Some(16)).is_empty());
    let cheap = profile(
        &SEATED_GOV.replace("\"1000000\"", "\"999999\""),
        ADAPTIVE_FAUCET,
    );
    assert_eq!(failed(&cheap, Some(16)), ["bond_beyond_faucet_reach"]);
    let flat = profile(SEATED_GOV, "pow_adaptive_lookback_blocks = 64");
    assert_eq!(failed(&flat, Some(16)), ["adaptive_faucet_difficulty"]);
    let no_lookback = profile(
        SEATED_GOV,
        &ADAPTIVE_FAUCET.replace("lookback_blocks = 64", "lookback_blocks = 0"),
    );
    assert_eq!(
        failed(&no_lookback, Some(16)),
        ["adaptive_faucet_difficulty"]
    );
    // A live faucet paying more than the profile says is measured against the live amount.
    let (ok, detail) = seated.bond_beyond_faucet_reach(Some(&Quantity::from(25_001_u32)));
    assert!(!ok, "{detail}");
    assert!(
        seated
            .bond_beyond_faucet_reach(Some(&Quantity::from(100_u32)))
            .0
    );
    let disabled = SeatingProfile::from_toml(&format!(
        "[gov]\n{SEATED_GOV}\n[torii.faucet]\nenabled = false\n"
    ))
    .unwrap();
    assert!(disabled.faucet.is_none());
    assert!(failed(&disabled, Some(16)).is_empty());
    assert!(SeatingProfile::from_toml("[torii.faucet]\nenabled = true\namount = \"0\"\n").is_err());
}

#[test]
fn juries_windows_and_coordination_are_enforced() {
    let unset = profile(
        &SEATED_GOV.replace("coordination_council_size = 5\n", ""),
        ADAPTIVE_FAUCET,
    );
    assert_eq!(
        failed(&unset, Some(16)),
        ["citizens_cover_bodies", "coordination_council_explicit"]
    );
    let short_window = profile(
        &SEATED_GOV.replace(
            "survivor_freeze_phase_blocks = 100",
            "survivor_freeze_phase_blocks = 15",
        ),
        ADAPTIVE_FAUCET,
    );
    assert_eq!(failed(&short_window, Some(16)), ["windows_cover_corpus"]);
    let tight_registration = profile(
        &SEATED_GOV.replace(
            "registration_phase_blocks = 300",
            "registration_phase_blocks = 16",
        ),
        ADAPTIVE_FAUCET,
    );
    assert_eq!(
        failed(&tight_registration, Some(16)),
        ["windows_cover_corpus"]
    );
    let small_corpus = profile(
        &SEATED_GOV.replace("max_corpus_entries = 16", "max_corpus_entries = 8"),
        ADAPTIVE_FAUCET,
    );
    assert_eq!(failed(&small_corpus, Some(16)), ["corpus_covers_juries"]);
    let anonymous = profile(
        &SEATED_GOV.replace("confirmation_jury_size = 7", "confirmation_jury_size = 2"),
        ADAPTIVE_FAUCET,
    );
    assert_eq!(failed(&anonymous, Some(16)), ["hidden_ballot_anonymity"]);
    let large_jury = profile(
        &SEATED_GOV
            .replace("policy_jury_size = 9", "policy_jury_size = 25")
            .replace("max_corpus_entries = 16", "max_corpus_entries = 25"),
        ADAPTIVE_FAUCET,
    );
    assert_eq!(large_jury.minimum_citizens(), 28);
    assert_eq!(
        failed(&large_jury, Some(27)),
        ["policy_jury_confirmation_margin"]
    );
    assert!(failed(&large_jury, Some(28)).is_empty());
    assert!(
        failed(&large_jury, None).contains(&"policy_jury_confirmation_margin"),
        "a jury above 20 seats cannot be proven without a citizen count"
    );
}

#[test]
fn seating_keys_replace_only_the_parliament_profile() {
    let canonical_table: toml::Table = toml::from_str(CANONICAL_TAIRA_PROFILE).unwrap();
    let mut config: toml::Table = toml::from_str(
        "chain = \"x\"\n[gov]\ncitizenship_escrow_account = \"escrow\"\nrules_committee_size = 50\n\
         [torii.faucet]\nenabled = true\namount = \"25000\"\npow_difficulty_bits = 8\n",
    )
    .unwrap();
    apply_seating_keys(&mut config, &canonical_table).unwrap();
    let gov = config["gov"].as_table().unwrap();
    assert_eq!(gov["citizenship_escrow_account"].as_str(), Some("escrow"));
    for key in GOV_SEATING_KEYS {
        assert_eq!(gov.get(key), canonical_table["gov"].get(key), "{key}");
    }
    let faucet = config["torii"]["faucet"].as_table().unwrap();
    assert_eq!(faucet["pow_difficulty_bits"].as_integer(), Some(8));
    for key in FAUCET_SEATING_KEYS {
        assert_eq!(
            faucet.get(key),
            canonical_table["torii"]["faucet"].get(key),
            "{key}"
        );
    }
    assert_eq!(config["chain"].as_str(), Some("x"));
    assert!(failed(&SeatingProfile::from_config(&config).unwrap(), Some(16)).is_empty());

    let mut without_faucet: toml::Table = toml::from_str("chain = \"x\"\n").unwrap();
    apply_seating_keys(&mut without_faucet, &canonical_table).unwrap();
    assert!(without_faucet.get("torii").is_none());
    let mut malformed: toml::Table = toml::from_str("gov = 1\n").unwrap();
    assert!(apply_seating_keys(&mut malformed, &canonical_table).is_err());
    assert_eq!(
        canonical_seating_config_toml(),
        canonical_seating_config_toml(),
        "the seated fixture renders deterministically"
    );
    assert!(
        failed(
            &SeatingProfile::from_toml(&canonical_seating_config_toml()).unwrap(),
            Some(16)
        )
        .is_empty()
    );
}

#[test]
fn citizen_instructions_seat_every_citizen_and_the_census_counts_them() {
    let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    let asset = AssetDefinitionId::parse_address_literal(CANONICAL_XOR).unwrap();
    let citizens = [account(1), account(2), account(3)];
    let escrow = account(9);
    let proposer = account(10);
    let bond = Quantity::from(1_000_000_u32);
    let instructions = citizen_genesis_instructions(
        &citizens,
        &asset,
        &bond,
        &Quantity::from(1_000_u32),
        Some(&escrow),
        Some(&proposer),
    )
    .unwrap();
    assert_eq!(instructions.len(), 1 + citizens.len() * 3 + 1);
    let census = genesis_citizen_census(&instructions, &bond);
    assert_eq!(census.eligible, citizens.iter().cloned().collect());
    assert_eq!(census.underbonded, 0);
    assert_eq!(census.parliament_manager_grants, 0);
    assert!(census.registered_accounts.contains(&escrow));
    assert!(
        citizens
            .iter()
            .all(|citizen| census.registered_accounts.contains(citizen))
    );
    let minted = instructions
        .iter()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<iroha::data_model::isi::MintBox>()
        })
        .count();
    assert_eq!(minted, citizens.len());
    let grants = instructions
        .iter()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
        .map(|grant| match grant {
            GrantBox::Permission(grant) => {
                (grant.object.name().to_owned(), grant.destination.clone())
            }
            other => panic!("unexpected grant {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        grants,
        [("CanProposeSccpRouteGovernance".to_owned(), proposer.clone())]
    );

    // A bond below the configured amount is not eligible, and a Parliament manager is refused.
    let mut mixed = instructions.clone();
    mixed.push(
        RegisterCitizen {
            owner: account(4),
            amount: Quantity::from(999_999_u32),
        }
        .into(),
    );
    mixed.push(Grant::account_permission(CanManageParliament, proposer).into());
    let census = genesis_citizen_census(&mixed, &bond);
    assert_eq!(census.eligible.len(), 3);
    assert_eq!(census.underbonded, 1);
    assert_eq!(census.parliament_manager_grants, 1);
    let error = require_seated_genesis(&canonical(), &mixed)
        .unwrap_err()
        .to_string();
    assert!(error.contains("CanManageParliament"), "{error}");
    let error = require_seated_genesis(&canonical(), &instructions)
        .unwrap_err()
        .to_string();
    assert!(error.contains("citizens_cover_bodies"), "{error}");
    assert!(
        citizen_genesis_instructions(&citizens, &asset, &bond, &Quantity::from(0_u32), None, None)
            .unwrap()
            .len()
            == citizens.len() * 3
    );
}

#[test]
fn appended_genesis_transaction_is_instruction_only() {
    let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    let asset = AssetDefinitionId::parse_address_literal(CANONICAL_XOR).unwrap();
    let instructions = citizen_genesis_instructions(
        &[account(1)],
        &asset,
        &Quantity::from(1_000_000_u32),
        &Quantity::from(1_000_u32),
        None,
        None,
    )
    .unwrap();
    let mut document = norito::json!({"chain": "x", "transactions": [{"instructions": []}]});
    append_genesis_transaction(&mut document, &instructions).unwrap();
    let transactions = document["transactions"].as_array().unwrap();
    assert_eq!(transactions.len(), 2);
    let appended = transactions[1].as_object().unwrap();
    assert_eq!(
        appended.keys().map(String::as_str).collect::<Vec<_>>(),
        ["instructions", "ivm_triggers", "topology"]
    );
    assert_eq!(
        appended
            .get("instructions")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        3
    );
    assert!(append_genesis_transaction(&mut norito::json!({}), &instructions).is_err());
}

#[test]
fn citizen_client_config_signs_from_the_key_file_and_the_published_identity() {
    let template: toml::Table = toml::from_str(
        "chain = \"c\"\nnetwork_id = \"stale\"\ntorii_url = \"http://127.0.0.1:8080/\"\n\
         [account]\nchain_discriminant = 369\npublic_key = \"old\"\nprivate_key = \"old\"\n",
    )
    .unwrap();
    let key = KeyPair::try_from_seed(vec![7; 32], Algorithm::Ed25519).unwrap();
    let identity = Path::new("/network/genesis.expected_hash");
    let rendered: toml::Table = toml::from_str(
        &citizen_client_config(
            &template,
            key.public_key(),
            "citizen-07.private_key",
            identity,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(rendered["chain"].as_str(), Some("c"));
    assert!(
        rendered.get("network_id").is_none(),
        "inline identity goes stale on re-sign"
    );
    assert_eq!(
        rendered["network_id_file"].as_str(),
        Some("/network/genesis.expected_hash")
    );
    let account = rendered["account"].as_table().unwrap();
    assert_eq!(
        account["chain_discriminant"].as_integer(),
        Some(369),
        "the template's network context is retained"
    );
    assert_eq!(
        account["public_key"].as_str(),
        Some(key.public_key().to_string().as_str())
    );
    assert!(
        account.get("private_key").is_none(),
        "no inline citizen key"
    );
    assert_eq!(
        account["private_key_file"].as_str(),
        Some("citizen-07.private_key")
    );
    assert!(citizen_client_config(&toml::Table::new(), key.public_key(), "k", identity).is_err());
}

fn generated_genesis(instructions: Vec<InstructionBox>) -> iroha_genesis::RawGenesisTransaction {
    let topology = (110_u8..114)
        .map(|seed| {
            let validator = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap();
            iroha_genesis::GenesisTopologyEntry::new(
                PeerId::new(validator.public_key().clone()),
                iroha_crypto::bls_normal_pop_prove(validator.private_key()).unwrap(),
            )
        })
        .collect();
    let mut builder =
        iroha_genesis::GenesisBuilder::new_without_executor(TAIRA_CHAIN_ID.into(), ".")
            .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
            .append_parameter(Parameter::Custom(
                SumeragiNposParameters::default().into_custom_parameter(),
            ))
            .set_topology(topology);
    for instruction in instructions {
        builder = builder.append_instruction(instruction);
    }
    builder
        .build_raw()
        .unwrap()
        .with_chain_discriminant(TAIRA_CHAIN_DISCRIMINANT)
        .with_consensus_mode(iroha::data_model::parameter::system::SumeragiConsensusMode::Npos)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters")
}

#[cfg(unix)]
#[test]
fn seat_parliament_seats_a_generated_network_once() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    let directory = tempfile::tempdir().unwrap();
    let localnet = directory.path().join("network");
    fs::create_dir(&localnet).unwrap();
    fs::set_permissions(&localnet, fs::Permissions::from_mode(0o700)).unwrap();
    let asset = AssetDefinitionId::parse_address_literal(CANONICAL_XOR).unwrap();
    let proposer_key = KeyPair::try_from_seed(vec![40; 32], Algorithm::Ed25519).unwrap();
    let proposer = AccountId::new(proposer_key.public_key().clone());
    // Kagami names the published default governance account as the citizenship escrow.
    let published_escrow =
        iroha_config::parameters::defaults::governance::citizenship_escrow_account_id();
    let escrow = published_escrow.clone();
    let genesis = generated_genesis(vec![
        Register::domain(Domain::new(
            DomainId::parse_fully_qualified("universal.universal").unwrap(),
        ))
        .into(),
        Register::asset_definition(AssetDefinition::new(
            asset.clone(),
            "XOR",
            NumericSpec::fractional(9),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Register::account(Account::new(proposer.clone())).into(),
    ]);
    fs::write(
        localnet.join("genesis.json"),
        json::to_json_pretty(&genesis).unwrap(),
    )
    .unwrap();
    for index in 0..2 {
        fs::write(
            localnet.join(format!("peer{index}.toml")),
            format!(
                "chain = \"{TAIRA_CHAIN_ID}\"\n[gov]\ncitizenship_escrow_account = \"{escrow}\"\n\
                 [torii.faucet]\nenabled = true\namount = \"25000\"\nasset_definition_id = \"{CANONICAL_XOR}\"\n\
                 pow_adaptive_lookback_blocks = 64\npow_adaptive_claims_per_extra_bit = 0\npow_adaptive_max_extra_bits = 0\n"
            ),
        )
        .unwrap();
    }
    let client_key = KeyPair::try_from_seed(vec![42; 32], Algorithm::Ed25519).unwrap();
    fs::write(
        localnet.join("client.toml"),
        format!(
            "chain = \"{TAIRA_CHAIN_ID}\"\ntorii_url = \"http://127.0.0.1:8080/\"\n[account]\n\
             chain_discriminant = 369\npublic_key = \"{}\"\nprivate_key = \"{}\"\n",
            client_key.public_key(),
            ExposedPrivateKey(client_key.private_key().clone())
                .try_to_multihash_string()
                .unwrap()
        ),
    )
    .unwrap();
    let prior_network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"pre-seating genesis"),
        ));
    fs::write(
        localnet.join(GENESIS_EXPECTED_HASH_FILE),
        format!("{prior_network_id}\n"),
    )
    .unwrap();
    let args = SeatParliament {
        localnet_dir: localnet.clone(),
        citizens: DEFAULT_GENESIS_CITIZENS,
        fee_float: DEFAULT_FEE_FLOAT_XOR.parse().unwrap(),
        sccp_proposer_public_key: Some(proposer_key.public_key().clone()),
        citizen_dir: None,
    };
    let mut output = Vec::new();
    args.run_with_writer(&mut output).unwrap();
    let report: Value = json::from_slice(&output).unwrap();
    assert_eq!(report["schema"].as_str(), Some(SEAT_REPORT_SCHEMA_V1));
    assert_eq!(report["citizens"].as_u64(), Some(16));
    assert_eq!(
        report["next"].as_str(),
        Some(resign_instructions(prior_network_id).as_str())
    );
    assert_eq!(
        report["previous_network_id"].as_str(),
        Some(prior_network_id.to_string().as_str())
    );
    assert!(
        report["next"]
            .as_str()
            .unwrap()
            .contains("--expected-hash-out genesis.expected_hash --replace-expected-hash")
    );
    assert!(!report["next"].as_str().unwrap().contains("mv "));

    let citizen_dir = localnet.join(CITIZEN_DIRECTORY);
    assert_eq!(fs::metadata(&citizen_dir).unwrap().mode() & 0o777, 0o700);
    let manifest: CitizenManifestV1 =
        json::from_slice(&fs::read(citizen_dir.join(CITIZEN_MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(manifest.schema, CITIZEN_MANIFEST_SCHEMA_V1);
    assert_eq!(manifest.citizens.len(), 16);
    assert_eq!(manifest.citizenship_bond_amount, "1000000");
    assert_eq!(manifest.sccp_proposer, Some(proposer.to_string()));
    // The seated escrow is fresh: not the published one, not a citizen, and its key was never
    // written anywhere in the runtime directory.
    assert_eq!(
        report["citizenship_escrow_account"].as_str(),
        Some(manifest.citizenship_escrow_account.as_str())
    );
    let fresh_escrow = parse_account(&manifest.citizenship_escrow_account, "escrow").unwrap();
    assert_ne!(fresh_escrow, published_escrow);
    assert!(!published_accounts().contains(&fresh_escrow));
    assert!(
        manifest
            .citizens
            .iter()
            .all(|entry| entry.account_id != manifest.citizenship_escrow_account)
    );
    assert_eq!(
        fs::read_dir(&citizen_dir).unwrap().count(),
        1 + 2 * manifest.citizens.len(),
        "only the manifest and each citizen's key and client config"
    );
    for entry in &manifest.citizens {
        for file in
            std::iter::once(&entry.private_key_file).chain(entry.client_config_file.as_ref())
        {
            let metadata = fs::metadata(citizen_dir.join(file)).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600, "{file}");
        }
        let key: iroha_crypto::PrivateKey =
            fs::read_to_string(citizen_dir.join(&entry.private_key_file))
                .unwrap()
                .trim_end()
                .parse()
                .unwrap();
        let public: iroha_crypto::PublicKey = entry.public_key.parse().unwrap();
        assert_eq!(iroha_crypto::PublicKey::from(key), public);
        assert_eq!(entry.account_id, AccountId::new(public).to_string());
    }
    // Re-signing publishes the new identity; every citizen config then loads as that citizen.
    let network_id = iroha::data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"seated genesis")),
    );
    fs::write(
        localnet.join(GENESIS_EXPECTED_HASH_FILE),
        format!("{network_id}\n"),
    )
    .unwrap();
    for entry in &manifest.citizens {
        let path = citizen_dir.join(entry.client_config_file.as_ref().expect("client config"));
        let config = iroha::config::Config::load_file(&path)
            .unwrap_or_else(|error| panic!("citizen config {}: {error:?}", path.display()));
        assert_eq!(config.network_id, network_id);
        assert_eq!(config.key_pair.public_key().to_string(), entry.public_key);
    }

    let seated: iroha_genesis::RawGenesisTransaction =
        json::from_slice(&fs::read(localnet.join("genesis.json")).unwrap()).unwrap();
    let census = require_seated_localnet(&localnet, &seated).unwrap();
    assert_eq!(census.eligible.len(), 16);
    assert!(census.registered_accounts.contains(&fresh_escrow));
    assert!(
        !census.registered_accounts.contains(&escrow),
        "the published escrow is not registered by the seating"
    );
    assert_eq!(
        seated
            .instructions()
            .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
            .count(),
        1
    );
    let profile = localnet_seating_profile(&localnet).unwrap();
    assert!(failed(&profile, Some(16)).is_empty());
    for index in 0..2 {
        let peer: toml::Table = toml::from_str(
            &fs::read_to_string(localnet.join(format!("peer{index}.toml"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            peer["gov"]["citizenship_escrow_account"].as_str(),
            Some(manifest.citizenship_escrow_account.as_str())
        );
        assert_eq!(
            peer["torii"]["faucet"]["pow_adaptive_max_extra_bits"].as_integer(),
            Some(8)
        );
        assert_eq!(
            peer["torii"]["faucet"]["pow_max_anchor_age_blocks"].as_integer(),
            Some(6)
        );
        assert_eq!(
            fs::metadata(localnet.join(format!("peer{index}.toml")))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }

    // A seated network is never seated twice.
    let error = SeatParliament {
        citizen_dir: Some(directory.path().join("again")),
        ..args
    }
    .run_with_writer(&mut Vec::new())
    .unwrap_err()
    .to_string();
    assert!(error.contains("already registers citizens"), "{error}");

    // Validators pointed back at the published escrow are refused by the reset tooling.
    for index in 0..2 {
        let path = localnet.join(format!("peer{index}.toml"));
        let mut peer: toml::Table = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        set_citizenship_escrow(&mut peer, &published_escrow).unwrap();
        fs::write(&path, toml::to_string(&peer).unwrap()).unwrap();
    }
    let error = format!(
        "{:#}",
        require_seated_localnet(&localnet, &seated).unwrap_err()
    );
    assert!(error.contains("citizenship_escrow_is_custodial"), "{error}");
}

#[test]
fn seated_genesis_must_register_the_configured_escrow() {
    let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    let asset = AssetDefinitionId::parse_address_literal(CANONICAL_XOR).unwrap();
    let citizens = (1..=16).map(account).collect::<Vec<_>>();
    let bond = Quantity::from(1_000_000_u32);
    let profile = SeatingProfile::from_toml(&canonical_seating_config_toml()).unwrap();
    let unregistered =
        citizen_genesis_instructions(&citizens, &asset, &bond, &Quantity::from(0_u32), None, None)
            .unwrap();
    let error = require_seated_genesis(&profile, &unregistered)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("does not register the citizenship escrow"),
        "{error}"
    );
    let registered = citizen_genesis_instructions(
        &citizens,
        &asset,
        &bond,
        &Quantity::from(0_u32),
        Some(&fixture_citizenship_escrow()),
        None,
    )
    .unwrap();
    let census = require_seated_genesis(&profile, &registered).unwrap();
    assert_eq!(census.eligible.len(), 16);
}

#[cfg(unix)]
#[test]
fn seat_parliament_refuses_unseatable_requests() {
    use std::os::unix::fs::PermissionsExt as _;

    let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    let directory = tempfile::tempdir().unwrap();
    let localnet = directory.path().join("network");
    fs::create_dir(&localnet).unwrap();
    fs::set_permissions(&localnet, fs::Permissions::from_mode(0o700)).unwrap();
    let genesis = generated_genesis(Vec::new());
    fs::write(
        localnet.join("genesis.json"),
        json::to_json_pretty(&genesis).unwrap(),
    )
    .unwrap();
    fs::write(localnet.join("peer0.toml"), "[gov]\n").unwrap();
    let seat = |citizens: u32| SeatParliament {
        localnet_dir: localnet.clone(),
        citizens,
        fee_float: Quantity::from(1_000_u32),
        sccp_proposer_public_key: None,
        citizen_dir: None,
    };
    let error = format!(
        "{:#}",
        seat(8).run_with_writer(&mut Vec::new()).unwrap_err()
    );
    assert!(error.contains("citizens_cover_bodies"), "{error}");
    let error = format!(
        "{:#}",
        seat(16).run_with_writer(&mut Vec::new()).unwrap_err()
    );
    assert!(
        error.contains("does not register the citizenship asset"),
        "{error}"
    );
    assert!(!localnet.join(CITIZEN_DIRECTORY).exists());
    fs::set_permissions(&localnet, fs::Permissions::from_mode(0o755)).unwrap();
    let error = format!(
        "{:#}",
        seat(16).run_with_writer(&mut Vec::new()).unwrap_err()
    );
    assert!(error.contains("owner-only"), "{error}");
}

#[derive(clap::Parser, Debug)]
struct TairaCli {
    #[command(subcommand)]
    command: crate::taira::Command,
}

#[test]
fn seat_parliament_and_doctor_flags_parse() {
    let parsed =
        TairaCli::try_parse_from(["taira", "seat-parliament", "--localnet-dir", "/n"]).unwrap();
    let crate::taira::Command::SeatParliament(seat) = parsed.command else {
        panic!("seat-parliament parses");
    };
    assert_eq!(seat.citizens, DEFAULT_GENESIS_CITIZENS);
    assert_eq!(seat.fee_float, Quantity::from(1_000_u32));
    assert!(
        seat.sccp_proposer_public_key.is_none(),
        "no SCCP proposer by default"
    );
    assert!(seat.citizen_dir.is_none());
    for citizens in ["0", "257"] {
        assert!(
            TairaCli::try_parse_from([
                "taira",
                "seat-parliament",
                "--localnet-dir",
                "/n",
                "--citizens",
                citizens,
            ])
            .is_err(),
            "{citizens} citizens are out of range"
        );
    }
    let key = KeyPair::try_from_seed(vec![5; 32], Algorithm::Ed25519).unwrap();
    let parsed = TairaCli::try_parse_from([
        "taira",
        "seat-parliament",
        "--localnet-dir",
        "/n",
        "--sccp-proposer-public-key",
        &key.public_key().to_string(),
    ])
    .unwrap();
    let crate::taira::Command::SeatParliament(seat) = parsed.command else {
        panic!("seat-parliament parses");
    };
    assert_eq!(
        seat.sccp_proposer_public_key.as_ref(),
        Some(key.public_key())
    );
    assert!(parse_public_key("not-a-key").is_err());
    // Citizens act through `iroha gov parliament`; the Taira group has no second copy.
    assert!(
        TairaCli::try_parse_from(["taira", "citizen", "respond-invitation"]).is_err(),
        "citizen transitions live under `iroha gov parliament`"
    );
    let parsed = TairaCli::try_parse_from(["taira", "doctor", "--parliament"]).unwrap();
    let crate::taira::Command::Doctor(doctor) = parsed.command else {
        panic!("doctor parses");
    };
    assert!(doctor.parliament);
}

#[test]
fn sccp_genesis_instruction_uses_taira_defaults_and_a_fresh_nonce() {
    use iroha::data_model::{isi::sccp::InitializeSccpV1, sccp::params::SccpParametersV1};
    assert!(sccp_genesis_instruction([0; 32]).is_err());
    let first = fresh_sccp_reset_nonce().expect("nonce");
    let second = fresh_sccp_reset_nonce().expect("nonce");
    assert_ne!(first, second);
    let instruction = sccp_genesis_instruction(first).expect("instruction");
    let initialize = instruction
        .as_any()
        .downcast_ref::<InitializeSccpV1>()
        .expect("InitializeSccpV1");
    assert_eq!(initialize.reset_nonce, first);
    assert_eq!(initialize.parameters, SccpParametersV1::taira_default());
}

#[test]
fn resign_identity_requires_one_canonical_line() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(GENESIS_EXPECTED_HASH_FILE);
    let prior = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"prior genesis"),
    ));
    for text in [
        prior.to_string(),
        format!(" {prior}\n"),
        format!("{prior}\n\n"),
        "stale\n".to_owned(),
    ] {
        fs::write(&path, text).unwrap();
        assert!(read_prior_network_identity(&path).is_err());
    }
    fs::write(&path, format!("{prior}\n")).unwrap();
    assert_eq!(read_prior_network_identity(&path).unwrap(), prior);
    let next = resign_instructions(prior);
    assert!(next.contains(&format!("--replace-expected-hash '{prior}'")));
    assert!(next.contains("--expected-hash-out genesis.expected_hash"));
    assert!(next.contains("--nexus-context-output nexus-amx-context.v1.bin"));
    assert!(!next.contains(".next"));
}
