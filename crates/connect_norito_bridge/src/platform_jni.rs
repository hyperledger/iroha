//! Platform-gated JNI exports and their Java conversion helpers.
#![cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
))]
#![allow(clippy::missing_safety_doc)]
use super::*;
use iroha_data_model::{
    isi::privacy::SubmitPrivacyProofV1,
    privacy::{
        PRIVACY_CAPABILITY_ARCHIVE_MAX_BYTES_V1, PrivacyCapabilityArchiveValidationStatusV1,
        PrivacyExact12CapabilityManifestV1, validate_privacy_capability_archive_v1,
    },
};
mod account_address;
mod committed_transaction_inclusion;
mod confidential_prover;
mod gpu;
mod kagemusha_wallet_advance;
mod kagemusha_wallet_observation;
mod kagemusha_wallet_review;
mod privacy_intent;

include!("platform_jni/part_1.rs");
include!("platform_jni/part_2.rs");
include!("platform_jni/part_3.rs");
include!("platform_jni/private_settlement.rs");

#[cfg(test)]
mod privacy_capability_network_tests;
