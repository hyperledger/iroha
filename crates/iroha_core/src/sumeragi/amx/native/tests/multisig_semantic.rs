//! Intrinsic native multisig causes remain terminal without invented retry provenance.

use super::*;

#[test]
fn native_multisig_semantic_cause_is_terminal_and_preserves_exact_diagnostic() {
    use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
    use iroha_data_model::{account::MultisigPolicyError, block::BlockHeader};
    use std::num::NonZeroU64;

    for original in [
        MultisigPolicyError::MemberWeightZero,
        MultisigPolicyError::ZeroThreshold,
        MultisigPolicyError::ThresholdExceedsTotal {
            threshold: 4,
            total_weight: 3,
        },
        MultisigPolicyError::UnsupportedVersion(2),
    ] {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state
            .try_block(BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0))
            .unwrap();
        let mut attempt = block.try_transaction().unwrap();
        assert!(attempt.execution_deferral().is_none());
        let diagnostic = leg_decode_error(AmxLegDecodeErrorV1::Multisig(original), &mut attempt);
        let Error::InvariantViolation(message) = diagnostic else {
            panic!("same terminal instruction diagnostic");
        };
        assert_eq!(message.as_ref(), original.to_string());
        assert!(
            attempt.execution_deferral().is_none(),
            "intrinsic multisig rejection cannot acquire a local retry origin"
        );
        drop(attempt);
        drop(block);
        assert_eq!(
            state.view().height(),
            0,
            "a typed intrinsic cause grants no execution output"
        );
    }
}
