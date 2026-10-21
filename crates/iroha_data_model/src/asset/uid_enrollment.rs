//! Explicit asset enrollment before UID controls become mandatory for all holders.

use super::AssetDefinitionId;
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Permanent activation after every existing positive holder has been reconciled.
///
/// The native executor supplies the activation height. Activation neither assigns
/// identities nor changes balances, and there is no instruction to turn it off.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::uid_enrollment::AssetUidEnrollmentV1")]
pub struct AssetUidEnrollmentV1 {
    /// Exact Global asset whose retail holders require UID membership.
    pub asset_definition_id: AssetDefinitionId,
    /// Native block height that atomically installed mandatory enrollment.
    pub activated_at_height: u64,
}

/// Asset-owner enrollment of an exact non-retail system account.
///
/// FI accounts use their separate native FI registration. Neither category may
/// overlap retail UID membership or native escrow custody. Revocation preserves
/// this institutional category and existing funds while refusing new credits.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::uid_enrollment::AssetUidSystemAccountV1")]
pub struct AssetUidSystemAccountV1 {
    /// Exact Global asset.
    pub asset_definition_id: AssetDefinitionId,
    /// Explicit system account, for example the government destination.
    pub account_id: AccountId,
    /// Starts at one and advances exactly once for each issuer-authorized update.
    pub revision: u64,
    /// Whether this retained system account may receive new beneficial holdings.
    pub enabled: bool,
}

/// Owner-only activation status at an authenticated native ledger watermark.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::uid_enrollment::AssetUidEnrollmentViewV1")]
pub struct AssetUidEnrollmentViewV1 {
    /// Exact queried definition, including when enrollment has not been activated.
    pub asset_definition_id: AssetDefinitionId,
    /// `None` means aggregate UID rules do not yet cover every holder of this asset.
    pub enrollment: Option<AssetUidEnrollmentV1>,
    /// Authenticated ledger time captured with this observation.
    pub ledger_time_ms: u64,
    /// Committed height of the same native view.
    pub as_of_height: u64,
}
