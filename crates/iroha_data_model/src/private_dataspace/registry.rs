//! Bounded public registration and certified cursors for independently executed private roots.

use super::*;
use crate::{
    account::AccountId,
    parameter::{CustomParameter, CustomParameterId},
    sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1},
};

/// Absolute number of retained private-root registrations in one parent registry.
pub const MAX_PRIVATE_DATASPACE_ROOTS: u32 = 4096;

/// Domain-separated ordinary-write key for an exact full-width private dataspace record.
#[must_use]
pub fn private_dataspace_record_witness_key(dataspace: DataSpaceId) -> Vec<u8> {
    let mut key = b"iroha:private-dataspace:record:v1\0".to_vec();
    key.extend_from_slice(&dataspace.as_u64().to_be_bytes());
    key
}

/// Chain-governed admission limits. Missing policy disables new registrations.
///
/// Changing these limits does not revoke or reset already registered histories. The parent
/// authorizes this parameter through its ordinary parameter-governance corridor.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::private_dataspace::PrivateDataspaceAdmissionPolicy")]
#[norito(deny_unknown_fields)]
pub struct PrivateDataspaceAdmissionPolicy {
    /// Maximum total registrations, bounded by [`MAX_PRIVATE_DATASPACE_ROOTS`].
    pub max_registered_roots: u32,
    /// Maximum registrations charged to one original owner; zero disables admission.
    pub max_roots_per_owner: u32,
}

impl PrivateDataspaceAdmissionPolicy {
    /// Canonical on-chain parameter identifier.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        "private_dataspace_admission_v1"
            .parse()
            .expect("static parameter identifier")
    }

    /// Validate finite limits, including the explicit all-zero disabled policy.
    ///
    /// # Errors
    /// Rejects limits outside the protocol bound or a partially disabled policy.
    pub fn validate(&self) -> Result<(), PrivateDataspaceAnchorError> {
        require(
            self.max_registered_roots <= MAX_PRIVATE_DATASPACE_ROOTS
                && self.max_roots_per_owner <= self.max_registered_roots
                && (self.max_registered_roots == 0) == (self.max_roots_per_owner == 0),
            "invalid private-root admission limits",
        )
    }

    /// Encode a validated policy into its native custom parameter.
    ///
    /// # Errors
    /// Rejects invalid limits or JSON serialization failure.
    pub fn into_custom_parameter(self) -> Result<CustomParameter, PrivateDataspaceAnchorError> {
        self.validate()?;
        let payload = norito::json::to_json(&self).map_err(failure)?;
        Ok(CustomParameter::new(
            Self::parameter_id(),
            payload
                .parse::<iroha_primitives::json::Json>()
                .map_err(failure)?,
        ))
    }

    /// Decode the exact native parameter, preserving malformed-policy errors.
    ///
    /// # Errors
    /// Rejects a different parameter identity, malformed JSON or invalid limits.
    pub fn from_custom_parameter(
        parameter: &CustomParameter,
    ) -> Result<Self, PrivateDataspaceAnchorError> {
        require(
            parameter.id() == &Self::parameter_id(),
            "wrong private-root policy parameter",
        )?;
        let policy: Self = parameter.payload().try_into_any().map_err(failure)?;
        policy.validate()?;
        Ok(policy)
    }
}

/// Public owner authorization and contiguous child certificate cursor retained by the parent.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::private_dataspace::PrivateDataspaceRecord")]
#[norito(deny_unknown_fields)]
pub struct PrivateDataspaceRecord {
    /// Full-width registry key, checked against the signed child scope.
    pub dataspace_id: DataSpaceId,
    /// Canonical SNS dataspace alias whose active owner authorized the registration.
    pub alias: String,
    /// Exact original owner. Transfers never silently replace child consensus credentials.
    pub owner: AccountId,
    /// SNS ownership generation that authorized the immutable registration.
    pub ownership_generation: u64,
    /// Registered child authority and latest authenticated contiguous decision.
    pub anchor: PrivateDataspaceAnchorState,
}

impl PrivateDataspaceRecord {
    /// Validate persisted identity and child authority without conferring live SNS ownership.
    ///
    /// # Errors
    /// Rejects noncanonical aliases, zero ownership generations or malformed child state.
    pub fn validate(&self) -> Result<(), PrivateDataspaceAnchorError> {
        let selector =
            NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, &self.alias).map_err(failure)?;
        require(
            selector.normalized_label() == self.alias && self.ownership_generation != 0,
            "noncanonical private-root alias or zero ownership generation",
        )?;
        self.anchor.validate()?;
        require(
            self.anchor.registration().parent_scope()?.1 == self.dataspace_id,
            "private-root record key differs from child scope",
        )
    }

    /// Dataspace identity from the validated immutable registration.
    #[must_use]
    pub fn dataspace_id(&self) -> DataSpaceId {
        self.dataspace_id
    }

    /// Domain-separated ordinary-write key for proving this exact record against a parent result.
    #[must_use]
    pub fn witness_key(&self) -> Vec<u8> {
        private_dataspace_record_witness_key(self.dataspace_id)
    }
}

/// Canonical sorted registry. It contains only public credentials, commitments and ownership.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::private_dataspace::PrivateDataspaceRegistry")]
#[norito(deny_unknown_fields)]
pub struct PrivateDataspaceRegistry {
    records: Vec<PrivateDataspaceRecord>,
}

impl PrivateDataspaceRegistry {
    /// Validate a restored registry independently of the current admission limits.
    ///
    /// # Errors
    /// Rejects excessive records, duplicate identities/aliases, mixed parents or invalid authority.
    pub fn validate(&self) -> Result<(), PrivateDataspaceAnchorError> {
        require(
            self.records.len() <= MAX_PRIVATE_DATASPACE_ROOTS as usize,
            "private-root registry exceeds bound",
        )?;
        let mut aliases = std::collections::BTreeSet::new();
        let mut previous = None;
        let mut parent = None;
        for record in &self.records {
            record.validate()?;
            let (record_parent, dataspace) = record.anchor.registration().parent_scope()?;
            require(
                previous.is_none_or(|id| id < dataspace) && aliases.insert(&record.alias),
                "private-root registry identities are not unique and sorted",
            )?;
            require(
                parent.is_none_or(|id| id == record_parent),
                "private-root registry contains different parents",
            )?;
            previous = Some(dataspace);
            parent = Some(record_parent);
        }
        Ok(())
    }

    /// Look up one full-width dataspace identity.
    #[must_use]
    pub fn get(&self, dataspace: DataSpaceId) -> Option<&PrivateDataspaceRecord> {
        self.records
            .binary_search_by_key(&dataspace, PrivateDataspaceRecord::dataspace_id)
            .ok()
            .map(|index| &self.records[index])
    }

    /// Public registrations in ascending dataspace order.
    #[must_use]
    pub fn records(&self) -> &[PrivateDataspaceRecord] {
        &self.records
    }

    /// Install one registration after the parent authenticates current SNS owner and generation.
    /// Exact retries preserve an advanced cursor; no retry can reset or replace a child genesis.
    ///
    /// # Errors
    /// Rejects malformed records, exhausted policy, another parent or conflicting registration.
    pub fn register_authorized(
        &mut self,
        policy: PrivateDataspaceAdmissionPolicy,
        alias: String,
        owner: AccountId,
        ownership_generation: u64,
        registration: PrivateDataspaceRegistration,
    ) -> Result<(), PrivateDataspaceAnchorError> {
        policy.validate()?;
        let dataspace_id = registration.parent_scope()?.1;
        let candidate = PrivateDataspaceRecord {
            dataspace_id,
            alias,
            owner,
            ownership_generation,
            anchor: PrivateDataspaceAnchorState::from_authorized_registration(registration)?,
        };
        candidate.validate()?;
        let dataspace = candidate.dataspace_id();
        let insertion = match self
            .records
            .binary_search_by_key(&dataspace, PrivateDataspaceRecord::dataspace_id)
        {
            Ok(index) => {
                let existing = &self.records[index];
                return require(
                    existing.alias == candidate.alias
                        && existing.owner == candidate.owner
                        && existing.ownership_generation == candidate.ownership_generation
                        && existing.anchor.registration() == candidate.anchor.registration(),
                    "private-root registration is immutable",
                );
            }
            Err(index) => index,
        };
        require(
            self.records.len() < policy.max_registered_roots as usize,
            "private-root admission is disabled or total quota is exhausted",
        )?;
        require(
            self.records
                .iter()
                .filter(|record| record.owner == candidate.owner)
                .count()
                < policy.max_roots_per_owner as usize,
            "private-root owner quota is exhausted",
        )?;
        require(
            !self
                .records
                .iter()
                .any(|record| record.alias == candidate.alias),
            "private-root alias is already registered",
        )?;
        if let Some(existing) = self.records.first() {
            require(
                existing.anchor.registration().parent_scope()?.0
                    == candidate.anchor.registration().parent_scope()?.0,
                "private-root registration belongs to another parent",
            )?;
        }
        self.records.insert(insertion, candidate);
        Ok(())
    }

    /// Apply a quorum-certified extension after checking current SNS ownership against registration.
    ///
    /// # Errors
    /// Rejects unknown/revoked ownership, replaced generations, invalid certificates or history gaps.
    pub fn apply_authorized(
        &mut self,
        dataspace: DataSpaceId,
        current_owner: &AccountId,
        current_ownership_generation: u64,
        anchor: &PrivateDataspaceAnchor,
    ) -> Result<PrivateDataspaceAnchorOutcome, PrivateDataspaceAnchorError> {
        let index = self
            .records
            .binary_search_by_key(&dataspace, PrivateDataspaceRecord::dataspace_id)
            .map_err(|_| {
                PrivateDataspaceAnchorError::Invalid("private root is not registered".into())
            })?;
        let record = &mut self.records[index];
        require(
            &record.owner == current_owner
                && record.ownership_generation == current_ownership_generation,
            "private-root owner or ownership generation changed",
        )?;
        record.anchor.apply(anchor)
    }
}

#[cfg(test)]
mod tests;
