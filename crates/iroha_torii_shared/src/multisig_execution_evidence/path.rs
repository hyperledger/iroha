//! Canonical multisig evidence route shared by runtime and std-only catalog exporters.

/// Fixed bounded read resource, with exact native account and hash selectors.
pub const MULTISIG_EXECUTION_EVIDENCE_PATH_V1: &str = "/v1/multisig/execution-evidence/{multisig_account_id}/{entrypoint_hash}/{proposal_id}/{instructions_hash}";
