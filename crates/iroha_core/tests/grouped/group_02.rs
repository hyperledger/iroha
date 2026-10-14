//! Grouped Iroha Core integration tests.

#[path = "../gov_min_duration.rs"]
mod gov_min_duration;
#[path = "../gov_plain_ballot.rs"]
mod gov_plain_ballot;
#[path = "../gov_plain_conviction.rs"]
mod gov_plain_conviction;
#[path = "../gov_plain_disabled.rs"]
mod gov_plain_disabled;
#[path = "../gov_plain_missing_ref.rs"]
mod gov_plain_missing_ref;
#[path = "../gov_plain_revote_monotonic.rs"]
mod gov_plain_revote_monotonic;
#[path = "../gov_propose_validation.rs"]
mod gov_propose_validation;
#[path = "../gov_referendum_window_guard.rs"]
mod gov_referendum_window_guard;
#[path = "../gov_slash_restitution.rs"]
mod gov_slash_restitution;
#[path = "../gov_sortition_seed.rs"]
mod gov_sortition_seed;
#[path = "../gov_zk_ballot.rs"]
mod gov_zk_ballot;
#[path = "../gov_zk_ballot_lock_verified.rs"]
mod gov_zk_ballot_lock_verified;
#[path = "../gov_zk_ballot_real_vk.rs"]
mod gov_zk_ballot_real_vk;
#[path = "../gov_zk_ballot_vk_status.rs"]
mod gov_zk_ballot_vk_status;
#[path = "../gov_zk_create_rejects_plain_conflict.rs"]
mod gov_zk_create_rejects_plain_conflict;
#[path = "../gov_zk_election_admission.rs"]
mod gov_zk_election_admission;
