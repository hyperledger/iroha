//! Actual compact catalog closure. Every signed source chain is rebuilt under
//! the common outer key, with exact descriptor/key equality across the roundtrip.
//! Two/three terminal component catalogs are not the complete release catalog.

/// Shared real controls-off Send and its authenticated predecessor builders.
#[path = "a_send_recursive.rs"]
pub mod send_chain;

use send_chain::load_outer;

include!("common/proof_fixtures/compact_catalog_body.rs");

fn send_terminal(source: &send_chain::AuthenticatedSend) -> Terminal<'_> {
    Terminal {
        key: &source.key,
        binding: &source.binding,
        proof: &source.proof,
        instances: &source.instances,
        public: &source.state.lineage,
        pallas: &source.pallas,
        opening: &source.opening,
    }
}

#[test]
fn forged_succinct_fold_requires_a_distinct_same_challenges_correction() {
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let honest = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let inputs = [honest.as_input(), honest.as_input()];
    let proof = forged_fold(&params, &inputs);
    let original =
        iroha_plonk_recursion::verify_fold(&params, &inputs, &proof, &FoldConfig::default())
            .unwrap();
    assert!(original.decide(&params, MemoryBudget::DEFAULT).is_err());
    let correction = deciding_correction(&params, &original);
    assert_ne!(&correction, original.g());
}

/// Genuine controls-off Send lineage under the common three-terminal compact key.
/// Its exact sources remain available for retained-Payment and Archive tests.
/// Load ancestry requires caller-supplied genuine native-BLS-authorized originals.
/// This component catalog does not establish complete payment qualification.
#[allow(dead_code)] // Archive consumes the full retained source and outer artifact.
pub(crate) struct CompactSendOmega {
    /// Complete genuine Send terminal and its exact statement/maps/signed sources.
    pub(crate) source: send_chain::AuthenticatedSend,
    /// Immutable common Bootstrap/Load/Send-mask0 outer verifying key.
    pub(crate) key: VerifyingKey<Ep>,
    /// Actual compact outer descriptor.
    pub(crate) binding: DescriptorBinding,
    /// Exact verified raw outer proof bytes.
    pub(crate) proof: Vec<u8>,
    /// Exact outer public columns.
    pub(crate) instances: Vec<Vec<Fq>>,
    /// Verified outer opening retained for the next operation's P fold.
    pub(crate) opening: FoldInput<Ep>,
    /// Fully decided transported V claim.
    pub(crate) vesta: AccumulatorT<Eq>,
    /// Exact three admitted terminal keys; internal A keys are excluded.
    pub(crate) catalog: Vec<VerifyingKey<Eq>>,
}

/// Rebuild the genuine Send predecessor from the existing three-terminal closure.
/// Every signed source is created after the common outer key is fixed. This
/// helper requires the native-BLS Load fixture and never admits Archive.
#[allow(dead_code)] // Used by genuine Archive integration fixtures.
pub(crate) fn compact_payer_send(fixture: &LoadFixture) -> CompactSendOmega {
    catalog_roundtrip(true, fixture).expect("three-terminal catalog produces Send")
}

fn catalog_roundtrip(include_send: bool, fixture: &LoadFixture) -> Option<CompactSendOmega> {
    let initial_root = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    let initial_load = load_chain::authenticated_load(&initial_root, fixture);
    let bootstrap = &initial_root.source;
    assert_eq!(
        bootstrap.binding, initial_load.binding,
        "uniform actual terminal A descriptor"
    );
    let catalog = vec![bootstrap.key.clone(), initial_load.key.clone()];
    let program = Program::new(
        bootstrap_terminal(bootstrap),
        catalog,
        &initial_root.binding,
    );
    let load = rebuild_bootstrap_load(&program, bootstrap, &initial_load, fixture);
    eprintln!(
        "COMPACT_TWO_TERMINAL_CLOSURE source_keys_equal=true common_key_bound_before_signing=true all_native_proofs=true transport=4800 full_catalog=false"
    );
    if !include_send {
        return None;
    }

    let initial_send = send_chain::run_send_from_load(&load, PROFILE, Some(2), false);
    assert_eq!(
        initial_send.binding, bootstrap.binding,
        "Send must share the exact admitted A descriptor"
    );
    let mut catalog = program.catalog.clone();
    catalog.push(initial_send.key.clone());
    let program = Program::new(
        bootstrap_terminal(bootstrap),
        catalog,
        &initial_root.binding,
    );
    let load = rebuild_bootstrap_load(&program, bootstrap, &initial_load, fixture);
    let send = send_chain::run_send_from_load(&load, PROFILE, Some(2), false);
    assert_eq!(send.binding, initial_send.binding);
    assert_eq!(send.key.to_bytes(), initial_send.key.to_bytes());
    assert_eq!(send.state.lineage[17], program.digest());
    let outer = program.prove(send_terminal(&send), "Send-mask0");
    send.pallas
        .decide(
            &PinnedParams::<Ep>::derive(16).unwrap(),
            MemoryBudget::DEFAULT,
        )
        .unwrap();
    eprintln!(
        "COMPACT_THREE_TERMINAL_CLOSURE source_keys_equal=true common_key_bound_before_signing=true all_native_proofs=true transport=4800 mask0_only=true full_catalog=false ordinary_finality_load_fixture=true"
    );
    Some(CompactSendOmega {
        source: send,
        key: program.key,
        binding: program.binding,
        proof: outer.proof,
        instances: outer.public,
        opening: outer.opening,
        vesta: outer.vesta,
        catalog: program.catalog,
    })
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Registered by receive_omega; other consumers select shared helpers only.
pub fn compact_bootstrap_load_catalog_rebinds_every_proof_and_key(fixture: &LoadFixture) {
    assert!(catalog_roundtrip(false, fixture).is_none());
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Registered by receive_omega; other consumers select shared helpers only.
pub fn compact_bootstrap_load_send_catalog_rebinds_every_proof_and_key(fixture: &LoadFixture) {
    let send = compact_payer_send(fixture);
    assert_eq!(send.proof.len(), 3712);
    assert_eq!(send.catalog.len(), 3);
    assert_eq!(
        send.source.state.lineage[17],
        send.key.kagemusha_digest(&send.binding).unwrap()
    );
    assert_eq!(send.source.maps.witness.after.core, send.source.state.core);
    assert_eq!(send.source.context.stage_count(), 5);
    assert_eq!(send.source.predecessor_omega.len(), 5120);
    assert_eq!(send.source.sigma.len(), 3296);
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Registered by receive_omega; other consumers select shared helpers only.
pub fn compact_predecessor_native_send_preserves_every_installed_stage_and_original(
    fixture: &LoadFixture,
) {
    let payer = compact_payer_load(fixture);
    let terminal = send_chain::run_send_from_load(&payer, PROFILE, Some(2), true);
    assert_eq!(terminal.state.lineage[17], payer.source.state.lineage[17]);
    eprintln!(
        "NATIVE_SEND_INSTALLED_DIFFERENTIAL all_five_a_four_w=true original_replay=true compact_predecessor=true mask=0 full_catalog=false"
    );
}
