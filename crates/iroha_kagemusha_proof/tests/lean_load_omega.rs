//! Genuine lean Load (one terminal A, no W, one own-receipt leaf, no own `Q_sigma`) proven from
//! a genuine rooted Bootstrap predecessor and wrapped by the complete Omega predicate.
//!
//! The ordinary receipt is synthetic component data bound to the predecessor's scheme, asset,
//! wallet and next ordinal. The Load circuit binds the receipt's terms and never verifies BLS
//! finality, which native code checks before Advance, so the proof chain under test is the
//! same as with a captured receipt. Run with a fresh `KAGEMUSHA_LOAD_OUTPUT` directory.

#![allow(clippy::duplicate_mod)] // Each chain retains its exact shared Bootstrap source types.

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
mod common;
#[path = "common/ordinary_load_fixture.rs"]
#[allow(dead_code)]
mod load_fixture;
#[path = "common/load_objects.rs"]
#[allow(dead_code)]
mod load_objects;

/// Shared genuine Bootstrap predecessor and lean Load continuation fixtures.
#[path = "common/proof_fixtures/a_load_recursive.rs"]
pub mod load_chain;

include!("common/proof_fixtures/load_omega_body.rs");

use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn synthetic_load_fixture() -> (LoadFixture, Arc<AtomicUsize>) {
    let output = PathBuf::from(
        std::env::var_os("KAGEMUSHA_LOAD_OUTPUT")
            .expect("fresh exclusive Load Omega original output directory"),
    );
    fs::create_dir(&output).expect("fresh output; no overwrite or implicit resume");
    let rebuilds = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&rebuilds);
    let fixture: LoadFixture = Arc::new(move |rooted| {
        let index = observed.fetch_add(1, Ordering::Relaxed);
        let directory = output.join(format!("predecessor-{index}"));
        fs::create_dir(&directory).expect("fresh originals for each selected predecessor");
        let (_, _, receipt) = load_objects::funded(&rooted.source.state);
        load_fixture::build(rooted, &receipt.bytes, &directory)
    });
    (fixture, rebuilds)
}

#[test]
#[ignore = "explicit genuine lean Load chain and complete outer proof at k16; run optimized"]
fn lean_load_reaches_complete_outer_predicate() {
    let (fixture, rebuilds) = synthetic_load_fixture();
    native_load_reaches_complete_outer_predicate(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 1);
}
