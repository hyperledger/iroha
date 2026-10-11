//! Shared native-BLS Load fixture with fresh originals for each exact predecessor.
//!
//! The captured ledger execution is synthetic component data. This fixture authenticates
//! its real BLS certificate, then uses the ordinary native four-A/three-W monetary source.

use super::{load_chain::LoadFixture, load_fixture, ordinary_load_receipt};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Admit the unchanged receipt before producing keys and bind every reconstruction to
/// a fresh original directory. The caller checks the exact final reconstruction count.
pub(crate) fn first_load_fixture(expected_rebuilds: usize) -> (LoadFixture, Arc<AtomicUsize>) {
    let capture = ordinary_load_receipt::first_capture();
    // Bind scheme, asset, wallet, ordinal and the actual local sigma relation to
    // the Bootstrap fixture before producing any key or proof.
    load_fixture::check_first_capture(&capture);
    let receipt = ordinary_load_receipt::verified_receipt(&capture);
    let output = PathBuf::from(
        std::env::var_os("KAGEMUSHA_LOAD_OUTPUT")
            .expect("fresh exclusive Load Omega original output directory"),
    );
    fs::create_dir(&output).expect("fresh output; no overwrite or implicit resume");
    let rebuilds = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&rebuilds);
    let fixture: LoadFixture = Arc::new(move |rooted| {
        let index = observed.fetch_add(1, Ordering::Relaxed);
        assert!(
            index < expected_rebuilds,
            "unexpected predecessor reconstruction"
        );
        let directory = output.join(format!("predecessor-{index}"));
        fs::create_dir(&directory).expect("fresh originals for each selected predecessor");
        load_fixture::build(rooted, &receipt, &directory)
    });
    (fixture, rebuilds)
}
