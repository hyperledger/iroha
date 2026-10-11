//! Crate-wide fixtures shared by unit tests.

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{NetworkId, block::BlockHeader};

/// Build a deterministic exact network identity for protocol fixtures.
pub(crate) fn synthetic_network_id(seed: &str) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        seed.as_bytes(),
    )))
}

/// Pre-admit one waiter node from the fixture's original finite pool.
///
/// Call before saturating that pool or acquiring the physical guard whose release
/// is observed. This helper allocates no fallback pool and preserves pool identity.
pub(crate) fn release_registration(
    budget: &iroha_allocation::AllocationBudget,
) -> iroha_allocation::release::ReleaseRegistration {
    use iroha_allocation::release::ReleaseRegistration;
    let mut reservation = budget
        .try_reserve(ReleaseRegistration::allocation_layout())
        .expect("original fixture pool admits its waiter before contention");
    let registration = ReleaseRegistration::from_reservation(&mut reservation)
        .expect("the original reservation funds the complete waiter node");
    assert!(registration.belongs_to(budget));
    registration
}

/// Run one exact test in this harness with private process-wide globals.
///
/// Returns `true` in the parent after the child completes exactly once, and
/// `false` in the child so the caller executes its original assertions.
pub(crate) fn run_in_isolated_harness(exact: &str) -> bool {
    const CHILD: &str = "IROHA_CORE_ISOLATED_UNIT_TEST_CHILD";
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(exact)) {
        return false;
    }
    let output = std::process::Command::new(
        std::env::current_exe().expect("resolve Core unit-test executable"),
    )
    .arg(exact)
    .args(["--exact", "--nocapture", "--test-threads=1"])
    .env(CHILD, exact)
    .output()
    .expect("execute exact isolated test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{exact} failed in its isolated harness\nstdout:\n{}\nstderr:\n{}",
        isolated_harness_diagnostic(&stdout),
        isolated_harness_diagnostic(&stderr),
    );
    assert!(
        stdout.contains(&format!("test {exact} ... ok"))
            && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "{exact} did not complete exactly once\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    true
}

// Child diagnostics cannot introduce another top-level libtest inventory into
// the parent's report. Keep every original message under a visible line prefix.
fn isolated_harness_diagnostic(output: &str) -> String {
    use std::fmt::Write as _;
    let mut diagnostic = String::new();
    for line in output.lines() {
        writeln!(diagnostic, "  | {line}").expect("write child diagnostics to String");
    }
    diagnostic
}

/// Produce the complete original AXT fixture after transient local contention.
///
/// Only the typed busy result is retried. Semantic, resource and verification
/// failures remain immediate test failures, and the request never changes.
pub(crate) fn prove_axt_bound_batch_when_available(
    batch: &fastpq_prover::TransitionBatch,
    binding: &iroha_data_model::nexus::AxtFastpqBinding,
) -> Vec<u8> {
    let limits = fastpq_prover::offline_compact::ProvingLimits::default().private_smt;
    let tree_bytes = limits
        .allocation_bytes(limits.max_updates, limits.max_unique_keys)
        .expect("the maintained fixture tree policy fits");
    let budget = iroha_allocation::AllocationBudget::new(tree_bytes);
    loop {
        let mut reservation = budget
            .try_reserve_bytes(tree_bytes)
            .expect("the original fixture pool is reusable after contention");
        let result =
            fastpq_prover::prove_axt_bound_batch(batch, binding, &budget, &mut reservation);
        drop(reservation);
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "private tree backing was released"
        );
        match result {
            Ok(proof) => return proof,
            Err(fastpq_prover::Error::ProducerBusy) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("original AXT fixture proof failed: {error:?}"),
        }
    }
}

mod tests {
    use super::synthetic_network_id;

    #[test]
    fn isolated_child_failure_preserves_cause_without_duplicate_libtest_records() {
        const EXACT: &str = "unit_test_support::tests::isolated_child_failure_preserves_cause_without_duplicate_libtest_records";
        const CAUSE: &str = "original isolated diagnostic failure";
        if std::env::var_os("IROHA_CORE_ISOLATED_UNIT_TEST_CHILD").as_deref()
            == Some(std::ffi::OsStr::new(EXACT))
        {
            panic!("{CAUSE}");
        }
        let failure = std::panic::catch_unwind(|| super::run_in_isolated_harness(EXACT))
            .expect_err("the real failing child must fail its parent boundary");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .expect("the original harness failure has a textual diagnostic");
        assert!(message.contains(CAUSE));
        assert!(message.contains(&format!("  | test {EXACT} ...")));
        assert!(message.contains("  | test result: FAILED. 0 passed; 1 failed;"));
        assert!(message.contains("  | running 1 test"));
        assert!(message.lines().all(|line| {
            !line.starts_with("running ")
                && !line.starts_with("test ")
                && !line.starts_with("test result:")
        }));
    }

    #[test]
    fn synthetic_network_id_is_deterministic_per_seed() {
        assert_eq!(synthetic_network_id("a"), synthetic_network_id("a"));
        assert_ne!(synthetic_network_id("a"), synthetic_network_id("b"));
    }
}
