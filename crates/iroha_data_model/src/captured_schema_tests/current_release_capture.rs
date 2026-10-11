//! Current first-release identity checks and explicit native capture inventory.
//!
//! Ordinary checks and the ignored capture printer share the same typed inventory.

use super::Case;

const CASES: &[Case] = &[Case::bidirectional::<crate::fastpq::FastpqTransitionBatch>(
    "iroha_data_model::fastpq::FastpqTransitionBatch",
)];

super::native_capture::owner_printer!(CASES);

#[test]
fn current_release_identities_match_native_capture() {
    for case in CASES {
        case.check();
    }
}
