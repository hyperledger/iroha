//! Certified restart of actual scheduled conversion and partially credited validator rewards.

#[test]
fn certified_reward_replay_resumes_unfinished_pages_and_actual_signed_claims() {
    crate::validation_fee::tests::runtime_wrapper_tests::reward_tests::scheduled_two_validator_reward_replay();
}
