//! Process-only crash observations for a single disposable unit-test subprocess.
//!
//! Production builds contain neither this owner nor its observations. Exiting at
//! an actual storage seam skips Rust destructors; it does not simulate power loss.

use super::{BlockHeader, HashOf, RecordName};
use std::sync::Mutex;

/// The exact native archive publication seam at which the owning child exits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Boundary {
    /// The certified carrier and State have published, but no archive write began.
    BeforeWrite,
    /// The complete stage was written and synced, before its canonical link.
    StageSynced,
    /// The canonical hard link and directory were synced; the stage still exists.
    CanonicalSynced,
    /// Canonical publication and durable stage removal finished.
    Complete,
}

/// Distinct from libtest success or assertion failure, proving the seam was reached.
pub(crate) const EXIT_CODE: i32 = 86;

static ARMED: Mutex<Option<(String, Boundary)>> = Mutex::new(None);

/// Exact canonical and staged record filenames for the observed original carrier.
pub(crate) fn record_names(height: u64, hash: HashOf<BlockHeader>) -> (String, String) {
    (
        RecordName::new(height, hash, false).as_str().to_owned(),
        RecordName::new(height, hash, true).as_str().to_owned(),
    )
}

/// Arm one exact original carrier in this disposable child process.
pub(crate) fn arm(height: u64, hash: HashOf<BlockHeader>, boundary: Boundary) {
    let mut armed = ARMED.lock().expect("process crash control is not poisoned");
    assert!(armed.is_none(), "one crash seam per disposable child");
    *armed = Some((
        RecordName::new(height, hash, false).as_str().to_owned(),
        boundary,
    ));
}

pub(super) fn observe(target: &RecordName, boundary: Boundary) {
    let armed = ARMED.lock().expect("process crash control is not poisoned");
    if armed
        .as_ref()
        .is_some_and(|(name, expected)| name == target.as_str() && *expected == boundary)
    {
        // Only the test's own subprocess can arm this observer. process::exit
        // deliberately skips State/Kura/TempDir destructors and shutdown flushes.
        std::process::exit(EXIT_CODE);
    }
}
