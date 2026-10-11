//! Receive terminal closure under one immutable native pinned-key Omega catalog.
//!
//! Funded Bootstrap/Load ancestry requires explicit native-BLS-authorized Load originals.
//! Bootstrap-only malformed-payment burn is unfunded.
//! Execution checks component closure; it does not
//! establish release admission, mobile qualification or a complete terminal catalog.
//! Funded cases in `native_load_tests` require a fresh `KAGEMUSHA_LOAD_OUTPUT`
//! directory and run individually in release with `--ignored --exact`.
#![allow(clippy::duplicate_mod)]
#[path = "receive_omega/native_load_tests.rs"]
mod native_load_tests;
/// Genuine staged Receive and its exact native terminal/source exports.
#[path = "a_receive_recursive.rs"]
pub mod receive_chain;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    omega::native::{Output, terminal_fold_inputs},
    operation_relation::map_effects::CREDIT_DOMAIN,
    q_sigma::native::IncomingMode,
    tree::{INDEXED_DEPTH, INDEXED_NODE_DOMAIN, IndexedLeaf, path_root},
};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{DescriptorBinding, VerifyingKey, verifier::verify_full};
use iroha_plonk_recursion::{FoldConfig, create_fold, verify_fold};
use receive_chain::compact_catalog::{self, Terminal};

/// Exact resulting receiver sources retained for subsequent `ArchiveStatus` tests.
/// This component artifact has not been admitted to the complete release catalog.
#[allow(dead_code)]
pub(crate) struct CompactReceiveOmega {
    pub(crate) source: receive_chain::AuthenticatedReceive,
    pub(crate) binding: DescriptorBinding,
    pub(crate) key: VerifyingKey<Ep>,
    pub(crate) output: Output,
    /// Native proof || P544 || V544, with no fabricated or re-encoded proof bytes.
    pub(crate) transport: Vec<u8>,
    /// Original public320 followed by the exact native transport.
    pub(crate) raw: Vec<u8>,
    pub(crate) credit_leaf: IndexedLeaf<Fp>,
    pub(crate) credit_slot: u32,
    pub(crate) credit_siblings: [Fp; INDEXED_DEPTH],
}

/// Build both signed source chains again after extending the immutable catalog,
/// then prove every Receive stage and close its exact four-slot native outer fold.
pub(crate) fn compact_receive(
    corrected: bool,
    fixture: compact_catalog::LoadFixture,
) -> CompactReceiveOmega {
    let (seed, initial_program, initial_wallets) =
        compact_catalog::compact_shared_wallet_seed(fixture);
    let (expected_binding, expected_key) =
        receive_chain::receive_terminal_identity(&initial_wallets);
    let (program, wallets) = seed.extend(
        &initial_program,
        &initial_wallets,
        &expected_binding,
        vec![expected_key.clone()],
    );
    drop(initial_program);
    drop(initial_wallets);
    drop(seed);
    let (wallets, correction) = if corrected {
        let (wallets, correction) = program.with_nondeciding_payer(wallets);
        (wallets, Some(correction))
    } else {
        (wallets, None)
    };
    let source = receive_chain::authenticated_receive_from_wallets(wallets, correction);
    assert_eq!(source.binding, expected_binding);
    assert_eq!(source.key.to_bytes(), expected_key.to_bytes());
    assert_eq!(program.catalog().len(), 3);
    wrap_receive(&program, source)
}

/// Close an already authenticated Receive under the supplied immutable program.
/// The caller can extend the common catalog with Send/Archive without duplicating
/// the four-slot selector, native outer producer or exact retained credit path.
pub(crate) fn wrap_receive(
    program: &compact_catalog::Program,
    source: receive_chain::AuthenticatedReceive,
) -> CompactReceiveOmega {
    assert_eq!(source.state.lineage[17], program.digest());
    let terminal = &source.terminal;
    let corrected = terminal.incoming_mode == IncomingMode::Corrected;
    let frame: [Fp; 69] = terminal.instances.as_slice().try_into().unwrap();
    let slots = terminal_fold_inputs(&frame, terminal.opening.clone()).unwrap();
    assert_eq!(slots[0], terminal.vesta_part.as_input());
    assert_eq!(slots[1], terminal.opening);
    assert_eq!(slots[2], terminal.predecessor_vesta.as_input());
    let params = iroha_plonk::pcs::ipa::PinnedParams::derive(16).unwrap();
    for slot in &slots {
        slot.decide(&params, MemoryBudget::DEFAULT).unwrap();
    }
    match terminal.incoming_mode {
        IncomingMode::Corrected => {
            assert!(
                terminal
                    .incoming_vesta
                    .decide(&params, MemoryBudget::DEFAULT)
                    .is_err()
            );
            assert_eq!(slots[3].g(), &terminal.incoming_correction);
            assert_ne!(slots[3].g(), terminal.incoming_vesta.g());
            assert_eq!(slots[3].challenges(), terminal.incoming_vesta.challenges());
        }
        IncomingMode::Accept => {
            assert_eq!(slots[3], terminal.incoming_vesta.as_input());
        }
        IncomingMode::Trivial => {
            assert!(!source.accepted_credit);
            let trivial =
                iroha_plonk_recursion::AccumulatorT::trivial(&params, MemoryBudget::DEFAULT)
                    .unwrap();
            assert_eq!(slots[3], trivial.as_input());
        }
    }
    // Dropping the fourth obligation changes the actual fold statement even if
    // another slot happens to contain equal bytes. The canonical native producer
    // independently derives and decides all four slots before proving.
    let (fold, _) = create_fold(
        &params,
        &slots,
        Fq::from(917).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    assert!(verify_fold(&params, &slots[..3], &fold, &FoldConfig::default()).is_err());
    for index in [42, 46, 62, 63, 64, 65] {
        let mut changed = terminal.instances.clone();
        changed[index] += Fp::ONE;
        assert!(
            verify_full(
                &params,
                &source.binding,
                &source.key,
                &[changed],
                &terminal.proof,
                MemoryBudget::DEFAULT,
            )
            .is_err()
        );
    }
    let outer = program.prove(
        Terminal {
            key: &source.key,
            binding: &source.binding,
            proof: &terminal.proof,
            instances: &terminal.instances,
            public: &source.state.lineage,
            pallas: &terminal.pallas,
            opening: &terminal.opening,
        },
        match terminal.incoming_mode {
            IncomingMode::Corrected => "Receive-corrected-burn",
            IncomingMode::Trivial => "Receive-trivial-burn",
            IncomingMode::Accept => "Receive-accept",
        },
    );
    let output = Output {
        proof: outer.proof,
        instances: outer.public,
        pallas: terminal.pallas.clone(),
        vesta: outer.vesta,
        opening: outer.opening,
    };
    let transport = output.transport();
    assert_eq!(transport.len(), 4800);
    let mut raw = receive_chain::public_bytes(&source.state.lineage);
    raw.extend_from_slice(&transport);
    assert_eq!(raw.len(), 5120);
    let credit_leaf = IndexedLeaf {
        key: source.statement[17],
        value: hash_with_domain(
            CREDIT_DOMAIN,
            &[
                source.statement[17],
                source.payment_digest,
                Fp::from(u64::from(!source.accepted_credit)),
            ],
        ),
        next_key: source.credit.leaf.next_key,
    };
    let credit_slot = source.credit.slot;
    let credit_siblings = source.credit.slot_siblings;
    assert_eq!(
        path_root(
            INDEXED_NODE_DOMAIN,
            credit_leaf.hash(),
            u64::from(credit_slot),
            &credit_siblings,
        ),
        source.state.lineage[16]
    );
    eprintln!(
        "RECEIVE_OMEGA_CLOSURE corrected={corrected} accepted_credit={} incoming_mode={:?} actual_proof=3712 transport=4800 four_inputs_decide=true fourth_slot_drop_rejected=true immutable_native_catalog=true exact_terminal_VK=true credit_membership=true full_catalog=false release_qualified=false",
        source.accepted_credit, terminal.incoming_mode
    );
    CompactReceiveOmega {
        source,
        binding: program.binding().clone(),
        key: program.verifying_key().clone(),
        output,
        transport,
        raw,
        credit_leaf,
        credit_slot,
        credit_siblings,
    }
}

/// No funded source or Load trust is needed to prove the malformed-input burn.
/// Both Bootstrap and Receive are rebuilt under one final two-terminal key.
#[test]
#[ignore = "genuine immutable Bootstrap+Receive catalog, all10A9W and final native Omega; run optimized"]
fn bootstrap_only_invalid_sigma_burn_closes_all_four_outer_obligations() {
    let (seed, initial_program, initial_receiver) =
        compact_catalog::compact_bootstrap_catalog_seed();
    let (binding, key) = receive_chain::bootstrap_burn_terminal_identity(&initial_receiver);
    let (program, receiver) = seed.extend(
        &initial_program,
        &initial_receiver,
        &binding,
        vec![key.clone()],
    );
    drop(initial_program);
    drop(initial_receiver);
    drop(seed);
    assert_eq!(program.catalog().len(), 2);
    let source = receive_chain::authenticated_bootstrap_burn(receiver);
    assert_eq!(source.binding, binding);
    assert_eq!(source.key.to_bytes(), key.to_bytes());
    assert!(!source.accepted_credit);
    let result = wrap_receive(&program, source);
    assert_eq!(
        result.source.state.core[8] - result.source.state.lineage[14],
        Fp::ZERO
    );
    assert_eq!(result.source.terminal.incoming_mode, IncomingMode::Trivial);
    eprintln!(
        "BOOTSTRAP_ONLY_INVALID_SIGMA_RECEIVE_OMEGA full10A9W=true canonical_custody_all19=true original_sigma_soft_false=true no_Load_trust=true adjusted_spendable_zero=true terminal_omega=true immutable_catalog_size=2 full_catalog=false release_qualified=false"
    );
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Other component harnesses include this shared builder.
pub fn genuine_receive_acceptance_closes_all_four_outer_obligations(
    fixture: compact_catalog::LoadFixture,
) {
    let _ = compact_receive(false, fixture);
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Other component harnesses include this shared builder.
pub fn genuine_receive_corrected_burn_closes_all_four_outer_obligations(
    fixture: compact_catalog::LoadFixture,
) {
    let _ = compact_receive(true, fixture);
}

/// Equal original claim bytes still occupy four prescribed obligation slots.
/// These fabricated frame cells test selection/folding only, not A admission.
#[test]
fn four_slot_selection_never_deduplicates_equal_claims() {
    let params = iroha_plonk::pcs::ipa::PinnedParams::<Eq>::derive(16).unwrap();
    let trivial =
        iroha_plonk_recursion::AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let (x, y) = trivial.g().coordinates().unwrap();
    let coordinates: Vec<_> = [x, y]
        .into_iter()
        .flat_map(|value| iroha_plonk_gadgets::statement::foreign_limbs(&value).map(Fp::from_u128))
        .collect();
    let mut frame = [Fp::ZERO; 69];
    frame[1] = Fp::from(16);
    for (point, challenges) in [(2, 6), (22, 26), (42, 46)] {
        frame[point..point + 4].copy_from_slice(&coordinates);
        frame[challenges..challenges + 16].copy_from_slice(trivial.challenges());
    }
    frame[62] = Fp::ONE;
    frame[65..69].copy_from_slice(&coordinates);
    let inputs = terminal_fold_inputs(&frame, trivial.as_input()).unwrap();
    assert_eq!(inputs, core::array::from_fn(|_| trivial.as_input()));
    let (fold, result) = create_fold(
        &params,
        &inputs,
        Fq::from(919).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    result.decide(&params, MemoryBudget::DEFAULT).unwrap();
    assert!(verify_fold(&params, &inputs[..3], &fold, &FoldConfig::default()).is_err());
}
