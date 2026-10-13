//! Lightweight UAID ↔ dataspace bindings maintained by the Space Directory.
//!
//! The canonical UAID capability manifests live in the main Sora Nexus dataspace.
//! Runtime components (portfolio aggregation, allowance enforcement, telemetry)
//! only need a compact view that says which accounts are permitted to act inside
//! which dataspaces. This module provides that mapping; higher-level services
//! are responsible for keeping it in sync with manifest activation/revocation.
use crate::state::WorldReadOnly;
use iroha_crypto::{Hash, HashOf, PublicKey};
use iroha_data_model::{
    account::{AccountId, rekey::AccountAliasDomain},
    nexus::{AssetPermissionManifest, DataSpaceCatalog, UniversalAccountId},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::error::ParseError;
use iroha_model_base::topology::DataSpaceId;
use iroha_schema::IntoSchema;
use mv::storage::StorageReadOnly;
use norito::codec::{Decode, Encode};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
/// Failure to resolve the one issuer key authorized by committed AXT policy.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum AxtIssuerResolutionError {
    /// A zero root is a policy placeholder, never an issuer-bearing manifest.
    #[error("AXT issuer policy has a zero manifest root")]
    ZeroManifestRoot,
    /// No active committed manifest matches the dataspace and root.
    #[error("no active Space Directory manifest matches the AXT policy")]
    MissingManifest,
    /// More than one active committed manifest matched the same policy identity.
    #[error("AXT policy resolves to multiple active Space Directory manifests")]
    AmbiguousManifest,
    /// The manifest UAID has no live canonical account binding.
    #[error("AXT issuer manifest has no live UAID account")]
    MissingUaidAccount,
    /// A committed index disagrees with the identity carried by its live value.
    #[error("AXT issuer identity indexes are inconsistent")]
    IdentityIndexMismatch,
    /// The manifest UAID/account is not committed as active in this dataspace.
    #[error("AXT issuer account is not bound to the policy dataspace")]
    MissingDataspaceBinding,
    /// V1 handles require one unambiguous signature-verification key.
    #[error("AXT issuer account must use a single-signature controller")]
    MultisigIssuer,
}
/// Exact committed issuer identity and verification key for one AXT policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxtIssuerBinding {
    /// UAID selected by the committed manifest root.
    pub issuer: UniversalAccountId,
    /// Sole single-signature controller resolved through the committed UAID indexes.
    pub public_key: PublicKey,
}
/// Resolve the exact AXT issuer key from committed Space Directory state.
///
/// Resolution is keyed by both dataspace and active manifest root. The matching manifest supplies
/// the UAID; the canonical UAID account index and dataspace binding then supply the sole authorized
/// single-signature key. Nothing carried by the handle participates in issuer selection.
///
/// # Errors
///
/// Fails closed for zero/missing/ambiguous manifests, stale indexes, absent
/// dataspace bindings, and multisignature controllers.
pub fn resolve_axt_issuer_binding(
    world: &(impl WorldReadOnly + ?Sized),
    dataspace: DataSpaceId,
    manifest_root: [u8; 32],
) -> Result<AxtIssuerBinding, AxtIssuerResolutionError> {
    if manifest_root.iter().all(|byte| *byte == 0) {
        return Err(AxtIssuerResolutionError::ZeroManifestRoot);
    }
    let mut matched_uaid = None;
    for (uaid, set) in world.space_directory_manifests().iter() {
        let Some(record) = set.get(&dataspace) else {
            continue;
        };
        if !record.is_active() {
            continue;
        }
        let canonical_manifest_hash: Hash = HashOf::new(&record.manifest).into();
        if record.manifest_hash != canonical_manifest_hash {
            return Err(AxtIssuerResolutionError::IdentityIndexMismatch);
        }
        if record.uaid() != *uaid || record.dataspace() != dataspace {
            return Err(AxtIssuerResolutionError::IdentityIndexMismatch);
        }
        if record.manifest_hash.as_ref() != manifest_root.as_slice() {
            continue;
        }
        if matched_uaid.replace(*uaid).is_some() {
            return Err(AxtIssuerResolutionError::AmbiguousManifest);
        }
    }
    let uaid = matched_uaid.ok_or(AxtIssuerResolutionError::MissingManifest)?;
    let account = world
        .uaid_accounts()
        .get(&uaid)
        .ok_or(AxtIssuerResolutionError::MissingUaidAccount)?;
    let account_details = world
        .accounts()
        .get(account)
        .ok_or(AxtIssuerResolutionError::MissingUaidAccount)?;
    if account_details.uaid() != Some(&uaid) {
        return Err(AxtIssuerResolutionError::IdentityIndexMismatch);
    }
    let is_bound = world
        .uaid_dataspaces()
        .get(&uaid)
        .is_some_and(|bindings| bindings.is_bound_to(dataspace, account));
    if !is_bound {
        return Err(AxtIssuerResolutionError::MissingDataspaceBinding);
    }
    let public_key = account
        .try_signatory()
        .cloned()
        .ok_or(AxtIssuerResolutionError::MultisigIssuer)?;
    Ok(AxtIssuerBinding {
        issuer: uaid,
        public_key,
    })
}
/// Lane identity extraction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneIdentityMetadataError {
    /// A UAID exists but is not active in the routed dataspace.
    MissingDataspaceBinding {
        /// Account UAID.
        uaid: UniversalAccountId,
        /// Routed dataspace.
        dataspace: DataSpaceId,
    },
    /// A UAID record exists for the target dataspace but its manifest is inactive.
    InactiveManifest {
        /// Account UAID.
        uaid: UniversalAccountId,
        /// Routed dataspace.
        dataspace: DataSpaceId,
    },
}
/// Extract lane identity metadata (UAID + capability tags) for transaction admission.
///
/// The lookup is scoped by account UAID and routed dataspace:
/// - if no account or no UAID exists, returns `(None, [])`
/// - if the UAID is not bound to the routed dataspace, returns
///   [`LaneIdentityMetadataError::MissingDataspaceBinding`]
/// - if the target manifest exists but is inactive, returns [`LaneIdentityMetadataError`]
/// - if the UAID has an active manifest for the target dataspace, returns tags from manifest notes
/// - if the UAID has a binding but no target manifest, returns `(Some(uaid), [])`
///
/// # Errors
/// Returns `InactiveManifest` for an inactive target manifest, or
/// `MissingDataspaceBinding` when the account UAID is not bound to the routed
/// dataspace.
pub fn extract_lane_identity_metadata(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    dataspace_id: DataSpaceId,
) -> Result<(Option<UniversalAccountId>, Vec<String>), LaneIdentityMetadataError> {
    let account_entry = match world.account(authority) {
        Ok(entry) => entry,
        Err(_) => return Ok((None, Vec::new())),
    };
    let Some(uaid) = account_entry.value().uaid().copied() else {
        return Ok((None, Vec::new()));
    };
    let manifest_record = world
        .space_directory_manifests()
        .get(&uaid)
        .and_then(|manifest_set| manifest_set.get(&dataspace_id).cloned());
    if let Some(record) = &manifest_record
        && !record.is_active()
    {
        return Err(LaneIdentityMetadataError::InactiveManifest {
            uaid,
            dataspace: dataspace_id,
        });
    }
    let is_bound = world
        .uaid_dataspaces()
        .get(&uaid)
        .is_some_and(|bindings| bindings.is_bound_to(dataspace_id, authority));
    if !is_bound {
        return Err(LaneIdentityMetadataError::MissingDataspaceBinding {
            uaid,
            dataspace: dataspace_id,
        });
    }
    if let Some(record) = manifest_record {
        let mut tags = BTreeSet::new();
        for entry in &record.manifest.entries {
            if let Some(note) = &entry.notes {
                let trimmed = note.trim();
                if !trimmed.is_empty() {
                    tags.insert(trimmed.to_string());
                }
            }
        }
        return Ok((Some(uaid), tags.into_iter().collect()));
    }
    Ok((Some(uaid), Vec::new()))
}
/// Resolve every dataspace-qualified account domain bound to an authority.
///
/// Lane-compliance policies operate on domain selectors, while production
/// accounts are canonical domainless subjects with one or more alias labels.
/// This helper maps those labels back to their concrete `DomainId` values.
///
/// # Errors
/// Returns a parse error if an authoritative account-alias lease is malformed
/// or an active alias cannot resolve its domain in the dataspace catalog.
pub fn extract_authority_domains(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    now_ms: u64,
) -> Result<Vec<DomainId>, ParseError> {
    let mut domains = BTreeSet::new();
    for alias in world.bound_account_aliases(authority) {
        if crate::sns::resolve_active_account_alias(
            world,
            world.dataspace_catalog(),
            &alias,
            now_ms,
        )
        .map_err(|_| ParseError::new("malformed authoritative SNS account-alias state"))?
        .as_ref()
            != Some(authority)
        {
            continue;
        }
        if let Some(domain_id) = alias.domain_id(world.dataspace_catalog())? {
            domains.insert(domain_id);
        }
    }
    Ok(domains.into_iter().collect())
}
/// Deterministic mapping from a UAID to the dataspaces/accounts where it is active.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::nexus::space_directory::UaidDataspaceBindings")]
pub struct UaidDataspaceBindings {
    entries: BTreeMap<DataSpaceId, BTreeSet<AccountId>>,
}
impl UaidDataspaceBindings {
    /// Returns `true` when the UAID is not associated with any dataspace.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Iterate dataspace bindings (`dataspace_id`, `accounts`).
    pub fn iter(&self) -> impl Iterator<Item = (&DataSpaceId, &BTreeSet<AccountId>)> {
        self.entries.iter()
    }
    /// Returns `true` when the provided account is bound to `dataspace`.
    #[must_use]
    pub fn is_bound_to(&self, dataspace: DataSpaceId, account_id: &AccountId) -> bool {
        self.entries
            .get(&dataspace)
            .is_some_and(|accounts| accounts.contains(account_id))
    }
    /// Returns the dataspace that owns the provided account, if any.
    #[must_use]
    pub fn dataspace_for_account(&self, account_id: &AccountId) -> Option<DataSpaceId> {
        self.entries
            .iter()
            .find(|(_, accounts)| accounts.contains(account_id))
            .map(|(dataspace, _)| *dataspace)
    }
    /// Adds an `(dataspace, account)` binding for the UAID.
    ///
    /// Returns `true` when the account was newly inserted.
    pub fn bind_account(&mut self, dataspace: DataSpaceId, account_id: AccountId) -> bool {
        self.entries
            .entry(dataspace)
            .or_default()
            .insert(account_id)
    }
    /// Retain only bindings for dataspaces included in `allowed`.
    ///
    /// Returns `true` when at least one dataspace binding was removed.
    pub fn retain_dataspaces(&mut self, allowed: &BTreeSet<DataSpaceId>) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|dataspace, _accounts| allowed.contains(dataspace));
        self.entries.len() != before
    }
}
/// Deterministic mapping from a canonical account id to the dataspaces and domains where it is
/// visible for routed read queries.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::nexus::space_directory::AccountScopeDirectoryEntry")]
pub struct AccountScopeDirectoryEntry {
    entries: BTreeMap<DataSpaceId, BTreeSet<AccountAliasDomain>>,
}
impl AccountScopeDirectoryEntry {
    /// Returns `true` when the account has no routed dataspace scope.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Iterate account scope entries (`dataspace_id`, `domains`).
    pub fn iter(&self) -> impl Iterator<Item = (&DataSpaceId, &BTreeSet<AccountAliasDomain>)> {
        self.entries.iter()
    }
    /// Ensure the account is visible in `dataspace`.
    pub fn ensure_dataspace(&mut self, dataspace: DataSpaceId) {
        self.entries.entry(dataspace).or_default();
    }
    /// Bind `domain_id` under `dataspace`.
    pub fn bind_domain(&mut self, dataspace: DataSpaceId, domain: AccountAliasDomain) {
        self.entries.entry(dataspace).or_default().insert(domain);
    }
    /// Resolve the stored dataspace -> alias-domain scope into fully-qualified [`DomainId`]s.
    ///
    /// # Errors
    /// Returns [`ParseError`] if the current dataspace catalog cannot qualify a stored
    /// dataspace/domain scope pair.
    pub fn hierarchy(
        &self,
        dataspace_catalog: &DataSpaceCatalog,
    ) -> Result<BTreeMap<DataSpaceId, BTreeSet<DomainId>>, ParseError> {
        let mut hierarchy = BTreeMap::new();
        for (dataspace, domains) in &self.entries {
            let resolved = hierarchy.entry(*dataspace).or_insert_with(BTreeSet::new);
            for domain in domains {
                let dataspace_alias = dataspace_catalog
                    .by_id(*dataspace)
                    .ok_or_else(|| ParseError::new("dataspace catalog entry is missing"))?
                    .alias
                    .clone();
                resolved.insert(DomainId::try_new(domain.name(), &dataspace_alias)?);
            }
        }
        Ok(hierarchy)
    }
    /// Retain only dataspaces included in `allowed`.
    ///
    /// Returns `true` when at least one dataspace entry was removed.
    pub fn retain_dataspaces(&mut self, allowed: &BTreeSet<DataSpaceId>) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|dataspace, _domains| allowed.contains(dataspace));
        self.entries.len() != before
    }
}
#[cfg(feature = "json")]
impl norito::json::JsonSerialize for UaidDataspaceBindings {
    fn json_serialize(&self, out: &mut String) {
        use base64::Engine as _;
        let bytes = norito::encode_canonical(self)
            .expect("UaidDataspaceBindings Norito serialization must succeed");
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        norito::json::JsonSerialize::json_serialize(&encoded, out);
    }
}
#[cfg(feature = "json")]
impl norito::json::JsonDeserialize for UaidDataspaceBindings {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use base64::Engine as _;
        let encoded = parser.parse_string()?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_str())
            .map_err(|err| norito::json::Error::Message(err.to_string()))?;
        norito::decode_canonical::<UaidDataspaceBindings>(&bytes)
            .map_err(|err| norito::json::Error::Message(err.to_string()))
    }
}
#[cfg(feature = "json")]
impl norito::json::JsonSerialize for AccountScopeDirectoryEntry {
    fn json_serialize(&self, out: &mut String) {
        use base64::Engine as _;
        let bytes = norito::encode_canonical(self)
            .expect("AccountScopeDirectoryEntry Norito serialization must succeed");
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        norito::json::JsonSerialize::json_serialize(&encoded, out);
    }
}
#[cfg(feature = "json")]
impl norito::json::JsonDeserialize for AccountScopeDirectoryEntry {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use base64::Engine as _;
        let encoded = parser.parse_string()?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_str())
            .map_err(|err| norito::json::Error::Message(err.to_string()))?;
        norito::decode_canonical::<AccountScopeDirectoryEntry>(&bytes)
            .map_err(|err| norito::json::Error::Message(err.to_string()))
    }
}
/// Manifest record tracked by the Space Directory host.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::nexus::space_directory::SpaceDirectoryManifestRecord")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema)]
pub struct SpaceDirectoryManifestRecord {
    /// Canonical manifest payload (UAID + dataspace scope).
    pub manifest: AssetPermissionManifest,
    /// Hash of the Norito-encoded manifest bytes.
    pub manifest_hash: Hash,
    /// Lifecycle information populated from activation/expiry/revocation events.
    pub lifecycle: SpaceDirectoryManifestLifecycle,
}
impl SpaceDirectoryManifestRecord {
    /// Construct a new record computing the canonical manifest hash.
    #[must_use]
    pub fn new(manifest: AssetPermissionManifest) -> Self {
        let manifest_hash: Hash = HashOf::new(&manifest).into();
        Self {
            manifest,
            manifest_hash,
            lifecycle: SpaceDirectoryManifestLifecycle::default(),
        }
    }
    /// Dataspace identifier extracted from the manifest.
    #[must_use]
    pub fn dataspace(&self) -> DataSpaceId {
        self.manifest.dataspace
    }
    /// UAID identifier extracted from the manifest.
    #[must_use]
    pub fn uaid(&self) -> UniversalAccountId {
        self.manifest.uaid
    }
    /// Returns `true` when the manifest is currently active (activated and not expired/revoked).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.lifecycle.is_active()
    }
}
/// Lifecycle metadata recorded for a manifest.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::nexus::space_directory::SpaceDirectoryManifestLifecycle")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, Default)]
pub struct SpaceDirectoryManifestLifecycle {
    /// Epoch (inclusive) when the manifest actually became active, if known.
    pub activated_epoch: Option<u64>,
    /// Epoch (inclusive) when the manifest expired naturally.
    pub expired_epoch: Option<u64>,
    /// Revocation metadata (if the manifest was revoked).
    pub revocation: Option<SpaceDirectoryManifestRevocation>,
}
/// Metadata describing a manifest revocation event.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::nexus::space_directory::SpaceDirectoryManifestRevocation")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema)]
pub struct SpaceDirectoryManifestRevocation {
    /// Epoch when the revocation took effect.
    pub epoch: u64,
    /// Optional textual reason captured by the host.
    pub reason: Option<String>,
}
impl SpaceDirectoryManifestLifecycle {
    /// Mark the manifest as activated at the provided epoch (clearing expiry/revocation markers).
    pub fn mark_activated(&mut self, epoch: u64) {
        self.activated_epoch = Some(epoch);
        self.expired_epoch = None;
        self.revocation = None;
    }
    /// Record the epoch when the manifest expired.
    pub fn mark_expired(&mut self, epoch: u64) {
        self.expired_epoch = Some(epoch);
    }
    /// Record a revocation event (epoch + optional reason).
    pub fn mark_revoked(&mut self, epoch: u64, reason: Option<String>) {
        self.revocation = Some(SpaceDirectoryManifestRevocation { epoch, reason });
    }
    /// Returns `true` when the manifest has been activated and not expired/revoked.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.activated_epoch.is_some() && self.expired_epoch.is_none() && self.revocation.is_none()
    }
}
/// Deterministic mapping from dataspace id to manifest record for a UAID.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::nexus::space_directory::SpaceDirectoryManifestSet")]
#[derive(Debug, Clone, Default, PartialEq, Eq, Encode, Decode, IntoSchema)]
pub struct SpaceDirectoryManifestSet {
    entries: BTreeMap<DataSpaceId, SpaceDirectoryManifestRecord>,
}
impl SpaceDirectoryManifestSet {
    /// Returns true when no manifests are recorded for the UAID.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Inserts or replaces the manifest associated with `record.manifest.dataspace`.
    pub fn upsert(
        &mut self,
        record: SpaceDirectoryManifestRecord,
    ) -> Option<SpaceDirectoryManifestRecord> {
        self.entries.insert(record.dataspace(), record)
    }
    /// Removes the manifest bound to the provided dataspace.
    pub fn remove(&mut self, dataspace: &DataSpaceId) -> Option<SpaceDirectoryManifestRecord> {
        self.entries.remove(dataspace)
    }
    /// Fetch the manifest bound to the dataspace, if any.
    #[must_use]
    pub fn get(&self, dataspace: &DataSpaceId) -> Option<&SpaceDirectoryManifestRecord> {
        self.entries.get(dataspace)
    }
    /// Iterate manifests keyed by dataspace.
    pub fn iter(&self) -> impl Iterator<Item = (&DataSpaceId, &SpaceDirectoryManifestRecord)> {
        self.entries.iter()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::World;
    use base64::Engine as _;
    use iroha_crypto::Hash;
    use iroha_data_model::nexus::ManifestVersion;
    use iroha_data_model::{account::Account, domain::Domain, prelude::*};
    use iroha_test_samples::gen_account_in;
    use norito::json;
    fn sample_manifest(dataspace: u32) -> AssetPermissionManifest {
        AssetPermissionManifest {
            version: ManifestVersion::default(),
            uaid: UniversalAccountId::from_hash(Hash::new(b"uaid::manifest")),
            dataspace: DataSpaceId::new(u64::from(dataspace)),
            issued_ms: 123,
            activation_epoch: 7,
            expiry_epoch: None,
            entries: Vec::new(),
        }
    }
    #[test]
    fn record_computes_manifest_hash() {
        let manifest = sample_manifest(11);
        let expected_hash: Hash = HashOf::new(&manifest).into();
        let record = SpaceDirectoryManifestRecord::new(manifest.clone());
        assert_eq!(record.manifest, manifest);
        assert_eq!(record.manifest_hash, expected_hash);
        assert!(record.lifecycle.activated_epoch.is_none());
        let ambient_record = {
            let alternate_flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            SpaceDirectoryManifestRecord::new(manifest)
        };
        assert_eq!(
            ambient_record.manifest_hash, expected_hash,
            "manifest identity must ignore ambient Norito layout"
        );
    }
    #[test]
    fn first_release_manifest_record_binary_roundtrip_keeps_lifecycle() {
        let mut record = SpaceDirectoryManifestRecord::new(sample_manifest(11));
        record.lifecycle.mark_activated(13);
        let encoded = record.encode();
        let mut input = encoded.as_slice();
        let decoded = SpaceDirectoryManifestRecord::decode(&mut input)
            .expect("complete first-release manifest record must decode");
        assert_eq!(decoded, record);
        assert!(
            input.is_empty(),
            "manifest record decoder must consume the exact payload"
        );
    }
    #[test]
    fn manifest_set_upsert_replaces_existing_entry() {
        let mut set = SpaceDirectoryManifestSet::default();
        let first = SpaceDirectoryManifestRecord::new(sample_manifest(1));
        set.upsert(first.clone());
        assert!(!set.is_empty());
        assert_eq!(
            set.get(&DataSpaceId::new(1)).unwrap().manifest_hash,
            first.manifest_hash
        );
        let mut manifest = sample_manifest(1);
        manifest.activation_epoch = 999;
        let replacement = SpaceDirectoryManifestRecord::new(manifest.clone());
        let previous = set.upsert(replacement.clone()).unwrap();
        assert_eq!(previous.manifest_hash, first.manifest_hash);
        let stored = set.get(&DataSpaceId::new(1)).unwrap();
        assert_eq!(stored.manifest.entries, manifest.entries);
        assert_eq!(set.iter().count(), 1);
    }
    #[test]
    fn bindings_report_membership_by_dataspace() {
        let mut bindings = UaidDataspaceBindings::default();
        let dataspace = DataSpaceId::new(7);
        let (account_id, _) = gen_account_in("wonderland");
        assert!(!bindings.is_bound_to(dataspace, &account_id));
        bindings.bind_account(dataspace, account_id.clone());
        assert!(bindings.is_bound_to(dataspace, &account_id));
        assert!(!bindings.is_bound_to(DataSpaceId::new(8), &account_id));
    }
    #[test]
    fn bindings_json_roundtrip() {
        let mut bindings = UaidDataspaceBindings::default();
        let (account_id, _) = gen_account_in("wonderland");
        bindings.bind_account(DataSpaceId::new(9), account_id);
        let encoded = json::to_json(&bindings).expect("bindings should serialize to JSON");
        let decoded: UaidDataspaceBindings =
            json::from_str(&encoded).expect("bindings should deserialize from JSON");
        assert_eq!(decoded, bindings);
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &bindings,
            "iroha_core::nexus::space_directory::UaidDataspaceBindings",
        );
        assert!(
            json::from_str::<AccountScopeDirectoryEntry>(&encoded).is_err(),
            "UAID membership frame must not be accepted as account scope"
        );
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let ambient_encoded = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            json::to_json(&bindings).expect("bindings use ambient-independent JSON")
        };
        assert_eq!(ambient_encoded, encoded);
        let canonical_frame =
            norito::encode_canonical(&bindings).expect("encode canonical bindings frame");
        let alternate_frame = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&bindings).expect("encode alternate-layout bindings frame")
        };
        assert_ne!(alternate_frame, canonical_frame);
        let alternate_json = format!(
            "\"{}\"",
            base64::engine::general_purpose::STANDARD.encode(alternate_frame)
        );
        assert!(
            json::from_str::<UaidDataspaceBindings>(&alternate_json).is_err(),
            "alternate-layout bindings frame must fail the external JSON boundary"
        );
    }
    #[test]
    fn account_scope_entry_json_roundtrip() {
        let mut entry = AccountScopeDirectoryEntry::default();
        entry.ensure_dataspace(DataSpaceId::UNIVERSAL);
        entry.ensure_dataspace(DataSpaceId::new(12));
        let encoded = json::to_json(&entry).expect("scope entry should serialize to JSON");
        let decoded: AccountScopeDirectoryEntry =
            json::from_str(&encoded).expect("scope entry should deserialize from JSON");
        assert_eq!(decoded, entry);
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &entry,
            "iroha_core::nexus::space_directory::AccountScopeDirectoryEntry",
        );
        assert!(
            json::from_str::<UaidDataspaceBindings>(&encoded).is_err(),
            "account scope frame must not be accepted as UAID membership"
        );
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let ambient_encoded = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            json::to_json(&entry).expect("scope entry uses ambient-independent JSON")
        };
        assert_eq!(ambient_encoded, encoded);
        let canonical_frame =
            norito::encode_canonical(&entry).expect("encode canonical scope frame");
        let alternate_frame = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&entry).expect("encode alternate-layout scope frame")
        };
        assert_ne!(alternate_frame, canonical_frame);
        let alternate_json = format!(
            "\"{}\"",
            base64::engine::general_purpose::STANDARD.encode(alternate_frame)
        );
        assert!(
            json::from_str::<AccountScopeDirectoryEntry>(&alternate_json).is_err(),
            "alternate-layout scope frame must fail the external JSON boundary"
        );
    }
    fn world_with_uaid(
        uaid: UniversalAccountId,
        dataspace: DataSpaceId,
        with_manifest: bool,
        manifest_active: bool,
    ) -> (World, AccountId) {
        let (authority, _) = gen_account_in("wonderland");
        let domain_id: DomainId =
            DomainId::try_new("wonderland", "universal").expect("static domain id");
        let domain = Domain::new(domain_id.clone()).build(&authority);
        let account = Account::new(authority.clone())
            .with_uaid(Some(uaid))
            .build(&authority);
        let mut world = World::with([domain], [account], []);
        if with_manifest {
            let manifest = AssetPermissionManifest {
                version: ManifestVersion::default(),
                uaid,
                dataspace,
                issued_ms: 1,
                activation_epoch: 1,
                expiry_epoch: None,
                entries: Vec::new(),
            };
            let mut record = SpaceDirectoryManifestRecord::new(manifest);
            record.lifecycle.mark_activated(1);
            if !manifest_active {
                record.lifecycle.mark_expired(2);
            }
            let mut set = SpaceDirectoryManifestSet::default();
            set.upsert(record);
            world.space_directory_manifests.insert(uaid, set);
            if manifest_active {
                let mut bindings = UaidDataspaceBindings::default();
                bindings.bind_account(dataspace, authority.clone());
                world.uaid_dataspaces.insert(uaid, bindings);
            }
        }
        (world, authority)
    }
    fn active_manifest_root(
        world: &World,
        uaid: UniversalAccountId,
        dataspace: DataSpaceId,
    ) -> [u8; 32] {
        *world
            .space_directory_manifests
            .view()
            .get(&uaid)
            .and_then(|set| set.get(&dataspace))
            .expect("active manifest fixture")
            .manifest_hash
            .as_ref()
    }
    #[test]
    fn axt_issuer_resolution_uses_only_consistent_committed_identity() {
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::axt-issuer"));
        let dataspace = DataSpaceId::new(31);
        let (world, authority) = world_with_uaid(uaid, dataspace, true, true);
        let root = active_manifest_root(&world, uaid, dataspace);
        assert_eq!(
            resolve_axt_issuer_binding(&world.view(), dataspace, root),
            Ok(AxtIssuerBinding {
                issuer: uaid,
                public_key: authority
                    .try_signatory()
                    .expect("single-key fixture account")
                    .clone(),
            })
        );
        let mut accounts = world.accounts.block();
        accounts
            .get_mut(&authority)
            .expect("fixture account details")
            .set_uaid(None);
        accounts.commit();
        assert_eq!(
            resolve_axt_issuer_binding(&world.view(), dataspace, root),
            Err(AxtIssuerResolutionError::IdentityIndexMismatch)
        );
    }
    #[test]
    fn axt_issuer_resolution_rejects_missing_dataspace_binding() {
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::axt-unbound"));
        let dataspace = DataSpaceId::new(32);
        let (world, _) = world_with_uaid(uaid, dataspace, true, true);
        let root = active_manifest_root(&world, uaid, dataspace);
        let mut bindings = world.uaid_dataspaces.block();
        bindings.remove(uaid);
        bindings.commit();
        assert_eq!(
            resolve_axt_issuer_binding(&world.view(), dataspace, root),
            Err(AxtIssuerResolutionError::MissingDataspaceBinding)
        );
    }
    #[test]
    fn lane_identity_metadata_rejects_missing_dataspace_binding() {
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::lane-helper-missing"));
        let dataspace = DataSpaceId::new(17);
        let (world, authority) = world_with_uaid(uaid, dataspace, false, true);
        let world_view = world.view();
        let err = extract_lane_identity_metadata(&world_view, &authority, dataspace)
            .expect_err("UAID routing must require a dataspace binding");
        assert_eq!(
            err,
            LaneIdentityMetadataError::MissingDataspaceBinding { uaid, dataspace }
        );
    }
    #[test]
    fn lane_identity_metadata_rejects_inactive_target_manifest() {
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::lane-helper-inactive"));
        let dataspace = DataSpaceId::new(23);
        let (world, authority) = world_with_uaid(uaid, dataspace, true, false);
        let world_view = world.view();
        let err = extract_lane_identity_metadata(&world_view, &authority, dataspace)
            .expect_err("inactive target manifest must be rejected");
        assert_eq!(
            err,
            LaneIdentityMetadataError::InactiveManifest { uaid, dataspace }
        );
    }
}
