//! Funded Unload and Retiring proof chains using exact native-BLS Load originals.
//!
//! The two-terminal catalog and synthetic execution receipt are component inputs.
//! TODO: Compile and execute both cases on the current candidate; no release claim.

#[path = "../common/first_load_fixture.rs"]
mod first_load_fixture;
#[path = "../common/ordinary_load_fixture.rs"]
mod load_fixture;
#[path = "../common/ordinary_load_receipt.rs"]
mod ordinary_load_receipt;

use super::{
    bootstrap, bootstrap_objects, catalog::send_chain::load_outer::load_chain, common, load_objects,
};
use first_load_fixture::first_load_fixture;
use std::sync::atomic::Ordering;

#[test]
#[ignore = "native BLS receipt and genuine funded Unload/Retiring chains; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_wallet_proves_unload_and_retiring_with_all_owners() {
    let (fixture, rebuilds) = first_load_fixture(2);
    super::compact_loaded_wallet_proves_unload_and_retiring_with_all_owners(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and funded Unload/Retiring native differential and checkpoint replay; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_native_consuming_proves_and_restores_every_stage() {
    let (fixture, rebuilds) = first_load_fixture(2);
    super::installed_native_consuming_proves_and_restores_every_stage(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
fn funded_unload_uses_exact_authenticated_load_original() {
    use ff::Field;
    use iroha_kagemusha_proof::{admin_sigma::UnloadCircuit, witness::core_index as core};
    use iroha_pasta::Fp;
    let capture = ordinary_load_receipt::first_capture();
    let receipt = ordinary_load_receipt::verified_receipt(&capture);
    let (initial, _, _) = bootstrap_objects::enrollment();
    let (loaded, _) = load_fixture::monetary(&initial, &receipt);
    let (synthetic, _, _) = load_objects::funded(&initial);
    assert_ne!(
        loaded.successor.core[core::LOAD_REDEEM_ROOT],
        synthetic.successor.core[core::LOAD_REDEEM_ROOT]
    );
    let (witness, insertion) =
        super::unload_objects::transition(&loaded.successor, Some(&receipt), false);
    assert_eq!(witness.predecessor.core, loaded.successor.core);
    assert_eq!(witness.predecessor.rest, loaded.successor.rest);
    assert_eq!(witness.predecessor.lineage, loaded.successor.lineage);
    assert_eq!(witness.successor.core[core::BALANCE], Fp::from(70));
    assert_eq!(witness.successor.core[core::NEXT_REDEEM], Fp::ONE);
    assert_ne!(
        witness.successor.core[core::LOAD_REDEEM_ROOT],
        witness.predecessor.core[core::LOAD_REDEEM_ROOT]
    );
    assert_eq!(insertion.unwrap().slot, 2);
    let circuit = UnloadCircuit::new(&witness);
    let report = iroha_plonk::check::check_circuit(
        &circuit,
        12,
        &circuit.instances(),
        iroha_plonk::check::CheckMode::Strict,
    )
    .unwrap();
    assert!(report.is_satisfied());
}

#[test]
fn funded_unload_refuses_replaced_original_or_predecessor() {
    use ff::Field;
    use iroha_kagemusha_proof::witness::core_index as core;
    use iroha_pasta::Fp;
    let capture = ordinary_load_receipt::first_capture();
    let receipt = ordinary_load_receipt::verified_receipt(&capture);
    let (initial, _, _) = bootstrap_objects::enrollment();
    let (loaded, _) = load_fixture::monetary(&initial, &receipt);
    // Version, all identity words, ordinal, amount, fee and finality context.
    for offset in [0, 2, 34, 66, 130, 146, 162, 178, 250] {
        let mut changed = receipt;
        changed[offset] ^= 1;
        assert!(
            std::panic::catch_unwind(|| {
                super::unload_objects::transition(&loaded.successor, Some(&changed), false)
            })
            .is_err(),
            "changed Load original at {offset}"
        );
    }
    let (_, _, synthetic) = load_objects::funded(&initial);
    assert!(
        std::panic::catch_unwind(|| {
            super::unload_objects::transition(&loaded.successor, Some(&synthetic.bytes), false)
        })
        .is_err()
    );
    for field in [core::LOAD_REDEEM_ROOT, core::NEXT_LOAD] {
        let mut changed = loaded.successor;
        changed.core[field] += Fp::ONE;
        assert!(
            std::panic::catch_unwind(|| {
                super::unload_objects::transition(&changed, Some(&receipt), false)
            })
            .is_err(),
            "changed predecessor field {field}"
        );
    }
    assert!(
        std::panic::catch_unwind(|| {
            super::unload_objects::transition(&loaded.successor, None, false)
        })
        .is_err()
    );
}

#[test]
fn bootstrap_retiring_needs_no_load_original_and_keeps_lifecycle_checks() {
    use ff::Field;
    use iroha_kagemusha_proof::{
        admin_sigma::{RetiringCircuit, StateWitness},
        witness::core_index as core,
    };
    use iroha_pasta::Fp;
    let (mut initial, _, _) = bootstrap_objects::enrollment();
    for (lifecycle, expected_valid) in [(Fp::ONE, true), (Fp::from(2), false)] {
        initial.core[core::LIFECYCLE] = lifecycle;
        bootstrap::rebind(&mut initial);
        let before = StateWitness::from(&initial);
        let (witness, insertion) = super::unload_objects::transition(&before, None, true);
        assert!(insertion.is_none());
        assert_eq!(witness.successor.core[core::LIFECYCLE], Fp::from(2));
        assert_eq!(witness.successor.core[core::BALANCE], Fp::ZERO);
        assert_eq!(
            witness.successor.core[core::LOAD_REDEEM_ROOT],
            before.core[core::LOAD_REDEEM_ROOT]
        );
        let circuit = RetiringCircuit::new(&witness);
        let report = iroha_plonk::check::check_circuit(
            &circuit,
            12,
            &circuit.instances(),
            iroha_plonk::check::CheckMode::Strict,
        )
        .unwrap();
        assert_eq!(report.is_satisfied(), expected_valid);
    }
}
