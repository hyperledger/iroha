//! Actual authenticated Bootstrap sigma/Q/A1/W/A2 wrapped by the complete Omega
//! predicate. Layout diagnostics do not establish the production transport cap.

/// Shared authenticated Bootstrap proof-chain fixture.
#[path = "common/proof_fixtures/a_recursive.rs"]
pub mod bootstrap_chain;

/// Compact one-terminal rooted construction with explicit qualification scope.
#[path = "common/compact_bootstrap.rs"]
pub mod compact_bootstrap;

include!("common/proof_fixtures/bootstrap_omega_body.rs");

#[test]
#[ignore = "full authenticated Bootstrap chain and outer proof; run optimized"]
fn authenticated_bootstrap_reaches_complete_outer_predicate() {
    let _ = rooted_bootstrap_omega(true);
}

#[test]
#[ignore = "actual independently enrolled receiver Bootstrap with rooted Omega; run optimized"]
fn authenticated_receiver_bootstrap_binds_its_actual_rooted_outer_key() {
    let artifact = rooted_bootstrap_omega_with_identity(
        false,
        bootstrap_chain::SourceProfile::Tagged { buses: 3 },
        Some(2),
        bootstrap_chain::BootstrapIdentity::Receiver,
    );
    assert_eq!(
        artifact.source.state.core[5..7],
        [Fp::from(71), Fp::from(72)]
    );
    assert_eq!(
        artifact.source.state.lineage[17],
        artifact.key.kagemusha_digest(&artifact.binding).unwrap()
    );
}

#[test]
#[ignore = "actual authenticated source A using parallel serialized FF; run optimized"]
fn serialized_foreign_bootstrap_source_and_outer_inventory() {
    serialized_foreign_inventory(4);
}

#[test]
#[ignore = "actual authenticated five-bus source candidate and outer inventory; run optimized"]
fn five_bus_bootstrap_source_and_outer_inventory() {
    serialized_foreign_inventory(5);
}

#[test]
#[ignore = "actual explicit two-bus Q and three-bus A profiles, then full compact Omega; run optimized"]
fn reduced_q_three_bus_bootstrap_source_and_outer_inventory() {
    let bootstrap = bootstrap_chain::authenticated_bootstrap_with_q_layout(
        false,
        iroha_pasta::Fp::from(91),
        3,
        Some(2),
    );
    source_outer_inventory(&bootstrap, 3);
}

#[test]
#[ignore = "actual Q2/tagged A3 profile and complete compact Omega predicate; run optimized"]
fn tagged_three_bus_bootstrap_source_and_outer_inventory() {
    let bootstrap = bootstrap_chain::authenticated_bootstrap_with_profile(
        false,
        iroha_pasta::Fp::from(91),
        bootstrap_chain::SourceProfile::Tagged { buses: 3 },
        Some(2),
    );
    source_outer_inventory(&bootstrap, 3);
}

#[test]
#[ignore = "actual explicit two-bus Q and four-bus A profiles, then full compact Omega; run optimized"]
fn reduced_q_four_bus_bootstrap_source_and_outer_inventory() {
    let bootstrap = bootstrap_chain::authenticated_bootstrap_with_q_layout(
        false,
        iroha_pasta::Fp::from(91),
        4,
        Some(2),
    );
    source_outer_inventory(&bootstrap, 4);
}

#[test]
#[ignore = "genuine Q2/tagged A3 source and strict k16 secondary replay; no outer proof"]
fn tagged_three_bus_bootstrap_secondary_strict_and_unknown_inventory() {
    let bootstrap = bootstrap_chain::authenticated_bootstrap_with_profile(
        false,
        Fp::from(91),
        bootstrap_chain::SourceProfile::Tagged { buses: 3 },
        Some(2),
    );
    let (circuit, public, _) = wrapper(&bootstrap);
    let (spans, plan) = compact_layout(&circuit, &public, false)
        .expect("the full authenticated source did not produce a strict k16 secondary layout");
    assert_eq!(spans.ends()[2], 65_530);
    assert_eq!(plan.capacity(), 65_530);
    assert!(plan.primary_end() <= plan.capacity());
    assert!(plan.event_count() > 0);
    eprintln!(
        "AUTHENTICATED_SECONDARY_STRICT_INVENTORY_PASS events={} range={} known_unknown_equal=true actual_outer_proof=false full_catalog=false lineage_rebound=false",
        plan.event_count(),
        plan.primary_end()
    );
}

/// Deferred exact Bootstrap proof parity for metadata-only native Omega ownership.
#[path = "common/omega_rebuild.rs"]
mod omega_rebuild;
