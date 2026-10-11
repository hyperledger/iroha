//! Structures, traits and impls related to `Role`s.
pub use self::model::*;
use crate::{
    Identifiable, Registered, Registrable,
    account::AccountId,
    permission::{Permission, Permissions},
};
use iroha_data_model_derive::model;
use iroha_model_base::name::Name;
use std::{collections::BTreeMap, format, string::String, vec::Vec};
#[model]
mod model {
    use super::*;
    use derive_more::{Constructor, Display, FromStr};
    use getset::Getters;
    use iroha_data_model_derive::IdEqOrdHash;
    use iroha_schema::IntoSchema;
    use norito::codec::{Decode, Encode};
    /// Identification of a role.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        FromStr,
        Getters,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[repr(transparent)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::role::model::RoleId")]
    pub struct RoleId {
        /// Role name, should be unique .
        pub name: Name,
    }
    /// Role is a tag for a set of permission tokens.
    #[derive(Debug, Display, Clone, IdEqOrdHash, Decode, Encode, IntoSchema)]
    #[display("{id}")]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::role::model::Role")]
    pub struct Role {
        /// Unique name of the role.
        pub id: RoleId,
        /// Permission tokens.
        pub permissions: Permissions,
        /// Permission grant epochs (block heights), keyed by permission.
        ///
        /// This map is populated by the node at execution time (e.g. when a role is
        /// registered or a permission is granted/revoked). Clients typically
        /// don't provide it and start with an empty map.
        #[norito(default)]
        pub permission_epochs: BTreeMap<Permission, u64>,
    }
    /// Builder for [`Role`]
    #[derive(Debug, Display, Clone, Getters, IdEqOrdHash, Decode, Encode, IntoSchema)]
    #[getset(get = "pub")]
    #[display("{grant_to}: {inner}")]
    pub struct NewRole {
        /// Role definition being created.
        #[id(transparent)]
        pub inner: Role,
        /// First owner
        pub grant_to: AccountId,
    }
}

impl norito::json::FastJsonWrite for RoleId {
    fn write_json(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.name, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::JsonSerialize::json_serialize_to(&self.name, out)
    }
}

impl norito::json::JsonDeserialize for RoleId {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let name = Name::json_deserialize(parser)?;
        Ok(Self { name })
    }
}

impl norito::json::FastJsonWrite for NewRole {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("id", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.inner.id, out);
        out.push(',');
        norito::json::write_json_string("permissions", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.inner.permissions, out);
        out.push(',');
        norito::json::write_json_string("grant_to", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.grant_to, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"id\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.inner.id, out)?;
            out.push_str(",\"permissions\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.inner.permissions, out)?;
            out.push_str(",\"grant_to\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.grant_to, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl norito::json::JsonDeserialize for NewRole {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use norito::json::MapVisitor;
        let mut visitor = MapVisitor::new(parser)?;
        let mut id: Option<RoleId> = None;
        let mut permissions: Option<Permissions> = None;
        let mut grant_to: Option<AccountId> = None;
        while let Some(key) = visitor.next_key()? {
            match key.as_str() {
                "id" => {
                    if id.is_some() {
                        return Err(norito::json::Error::duplicate_field("id"));
                    }
                    id = Some(visitor.parse_value::<RoleId>()?);
                }
                "permissions" => {
                    if permissions.is_some() {
                        return Err(norito::json::Error::duplicate_field("permissions"));
                    }
                    permissions = Some(visitor.parse_value::<Permissions>()?);
                }
                "grant_to" => {
                    if grant_to.is_some() {
                        return Err(norito::json::Error::duplicate_field("grant_to"));
                    }
                    grant_to = Some(visitor.parse_value::<AccountId>()?);
                }
                other => return Err(norito::json::Error::unknown_field(other.to_owned())),
            }
        }
        visitor.finish()?;
        let id = id.ok_or_else(|| norito::json::Error::missing_field("id"))?;
        let permissions =
            permissions.ok_or_else(|| norito::json::Error::missing_field("permissions"))?;
        let grant_to = grant_to.ok_or_else(|| norito::json::Error::missing_field("grant_to"))?;
        Ok(Self {
            inner: Role {
                id,
                permissions,
                permission_epochs: BTreeMap::new(),
            },
            grant_to,
        })
    }
}

impl norito::json::JsonSerialize for Role {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("id", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.id, out);
        out.push(',');
        norito::json::write_json_string("permissions", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.permissions, out);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"id\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.id, out)?;
            out.push_str(",\"permissions\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.permissions, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl norito::json::JsonDeserialize for Role {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use norito::json::MapVisitor;
        let mut visitor = MapVisitor::new(parser)?;
        let mut id: Option<RoleId> = None;
        let mut permissions: Option<Permissions> = None;
        while let Some(key) = visitor.next_key()? {
            match key.as_str() {
                "id" => {
                    if id.is_some() {
                        return Err(norito::json::Error::duplicate_field("id"));
                    }
                    id = Some(visitor.parse_value::<RoleId>()?);
                }
                "permissions" => {
                    if permissions.is_some() {
                        return Err(norito::json::Error::duplicate_field("permissions"));
                    }
                    permissions = Some(visitor.parse_value::<Permissions>()?);
                }
                other => return Err(norito::json::Error::unknown_field(other.to_owned())),
            }
        }
        visitor.finish()?;
        let id = id.ok_or_else(|| norito::json::Error::missing_field("id"))?;
        let permissions =
            permissions.ok_or_else(|| norito::json::Error::missing_field("permissions"))?;
        Ok(Self {
            id,
            permissions,
            permission_epochs: BTreeMap::new(),
        })
    }
}
impl Role {
    /// Constructor.
    #[inline]
    pub fn new(id: RoleId, grant_to: AccountId) -> <Self as Registered>::With {
        NewRole::new(id, grant_to)
    }
    /// Get an iterator over [`permissions`](Permission) of the `Role`
    #[inline]
    pub fn permissions(&self) -> impl ExactSizeIterator<Item = &Permission> {
        self.permissions.iter()
    }
    /// Return the recorded epoch for the provided permission.
    #[inline]
    #[must_use]
    pub fn permission_epoch(&self, permission: &Permission) -> Option<u64> {
        self.permission_epochs.get(permission).copied()
    }
    /// Borrow the permission epoch map.
    #[inline]
    #[must_use]
    pub fn permission_epochs(&self) -> &BTreeMap<Permission, u64> {
        &self.permission_epochs
    }
    /// Fill missing permission epoch entries and drop stale ones.
    pub fn ensure_permission_epochs(&mut self, default_epoch: u64) {
        self.permission_epochs
            .retain(|perm, _| self.permissions.contains(perm));
        for perm in &self.permissions {
            self.permission_epochs
                .entry(perm.clone())
                .or_insert(default_epoch);
        }
    }
}
impl NewRole {
    /// Constructor
    #[must_use]
    #[inline]
    fn new(id: RoleId, grant_to: AccountId) -> Self {
        Self {
            grant_to,
            inner: Role {
                id,
                permissions: Permissions::new(),
                permission_epochs: BTreeMap::new(),
            },
        }
    }
    /// Add permission to the [`Role`]
    #[must_use]
    #[inline]
    pub fn add_permission(self, perm: impl Into<Permission>) -> Self {
        self.add_permission_with_epoch(perm, 0)
    }
    /// Add permission to the [`Role`] with an explicit epoch.
    #[must_use]
    #[inline]
    pub fn add_permission_with_epoch(mut self, perm: impl Into<Permission>, epoch: u64) -> Self {
        let perm = perm.into();
        self.inner.permissions.insert(perm.clone());
        // `epoch == 0` is treated as the implicit/default value and is omitted
        // from the sparse `permission_epochs` map to keep payloads compact.
        if epoch != 0 {
            self.inner.permission_epochs.entry(perm).or_insert(epoch);
        }
        self
    }
}
impl Registered for Role {
    type With = NewRole;
}
impl Registrable for NewRole {
    type Target = Role;
    #[inline]
    fn build(self, _authority: &AccountId) -> Self::Target {
        self.inner
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::Permission;
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::json::Json;
    #[test]
    fn role_json_roundtrip() {
        let name: Name = "auditor".parse().expect("role name");
        let id = RoleId::new(name);
        let mut permissions = Permissions::new();
        permissions.insert(Permission::new(
            "can_audit".into(),
            Json::new(norito::json!({"level": "basic"})),
        ));
        let role = Role {
            id,
            permissions,
            // Epoch `0` is the implicit default and omitted from JSON.
            permission_epochs: BTreeMap::new(),
        };
        let json = norito::json::to_json(&role).expect("serialize role");
        let mut decoded: Role = norito::json::from_json(&json).expect("deserialize role");
        assert_eq!(decoded, role);
        assert_eq!(decoded.permissions, role.permissions);
        assert!(decoded.permission_epochs().is_empty());
        decoded.ensure_permission_epochs(0);
        assert_eq!(decoded.permission_epochs().len(), 1);
        assert_eq!(
            decoded.permission_epoch(decoded.permissions().next().expect("permission")),
            Some(0)
        );
    }
    #[test]
    fn role_json_rejects_unknown_fields() {
        let role = Role {
            id: RoleId::new("auditor".parse().expect("role name")),
            permissions: Permissions::new(),
            permission_epochs: BTreeMap::new(),
        };
        let mut value = norito::json::to_value(&role).expect("serialize role");
        let norito::json::Value::Object(fields) = &mut value else {
            panic!("role must serialize as an object");
        };
        fields.insert("retired_alias".to_owned(), norito::json::Value::Bool(true));
        let error = norito::json::from_value::<Role>(value)
            .expect_err("unknown role fields must fail closed");
        assert!(matches!(
            error,
            norito::json::Error::UnknownField { field } if field == "retired_alias"
        ));
    }
    #[test]
    fn new_role_json_rejects_unknown_fields() {
        use iroha_crypto::{Algorithm, KeyPair};

        let keypair = KeyPair::try_from_seed(vec![0xA5; 32], Algorithm::Ed25519)
            .expect("derive checked role fixture keypair");
        let new_role = Role::new(
            RoleId::new("auditor".parse().expect("role name")),
            AccountId::new(keypair.public_key().clone()),
        );
        let mut value = norito::json::to_value(&new_role).expect("serialize new role");
        let norito::json::Value::Object(fields) = &mut value else {
            panic!("new role must serialize as an object");
        };
        fields.insert("legacy_owner".to_owned(), norito::json::Value::Bool(true));
        let error = norito::json::from_value::<NewRole>(value)
            .expect_err("unknown new-role fields must fail closed");
        assert!(matches!(
            error,
            norito::json::Error::UnknownField { field } if field == "legacy_owner"
        ));
    }
    #[test]
    fn role_permission_epochs_capture_epoch() {
        use iroha_crypto::{Algorithm, KeyPair};
        let name: Name = "auditor".parse().expect("role name");
        let id = RoleId::new(name);
        let perm = Permission::new("can_audit".into(), Json::new(norito::json!({})));
        let _domain: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").unwrap();
        let keypair = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("test fixture Ed25519 key generation should succeed");
        let account_id = AccountId::new(keypair.public_key().clone());
        let role = Role::new(id, account_id.clone())
            .add_permission_with_epoch(perm.clone(), 42)
            .build(&account_id);
        assert_eq!(role.permission_epoch(&perm), Some(42));
    }
    #[test]
    fn role_ensure_permission_epochs_fills_missing_and_prunes() {
        let name: Name = "auditor".parse().expect("role name");
        let id = RoleId::new(name);
        let perm = Permission::new("can_audit".into(), Json::new(norito::json!({})));
        let mut permissions = Permissions::new();
        permissions.insert(perm.clone());
        let mut role = Role {
            id,
            permissions,
            permission_epochs: BTreeMap::new(),
        };
        role.ensure_permission_epochs(9);
        assert_eq!(role.permission_epoch(&perm), Some(9));
        role.permissions.clear();
        role.ensure_permission_epochs(9);
        assert!(role.permission_epochs.is_empty());
    }
}
/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{NewRole, Role, RoleId};
}
// Provide a slice-based decoder for Role to satisfy event enum derives that
// require `DecodeFromSlice` at the always-bounded decode boundary.
impl<'a> norito::core::DecodeFromSlice<'a> for Role {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        // Use the adaptive bare decoder; it consumes the full slice.
        let mut cur = std::io::Cursor::new(bytes);
        let value = <Self as norito::codec::Decode>::decode(&mut cur)?;
        Ok((value, bytes.len()))
    }
}

/// [`RoleId`] with owner [`AccountId`] attached to it.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::role::RoleIdWithOwner")]
#[derive(
    Debug,
    Clone,
    derive_more::Constructor,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    norito::codec::Decode,
    norito::codec::Encode,
    iroha_schema::IntoSchema,
    crate::DeriveJsonDeserialize,
    crate::DeriveJsonSerialize,
)]
pub struct RoleIdWithOwner {
    /// [`AccountId`] of the owner.
    pub account: AccountId,
    /// [`RoleId`]  of the given role.
    pub id: RoleId,
}
impl core::fmt::Display for RoleIdWithOwner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}|{}", self.account, self.id)
    }
}
// One borrowed grammar boundary is shared by text and JSON storage keys.
// Each API retains its own account error owner; JSON must keep codec provenance.
// I105 accounts cannot contain `|`; the complete suffix is the role name,
// whose canonical Name grammar permits additional `|` characters.
fn role_id_with_owner_components(
    encoded: &str,
) -> Result<(&str, &str), iroha_model_base::error::ParseError> {
    encoded
        .split_once('|')
        .ok_or(iroha_model_base::error::ParseError::new(
            "RoleIdWithOwner must be formatted as `account|role`",
        ))
}
impl core::str::FromStr for RoleIdWithOwner {
    type Err = iroha_model_base::error::ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (account_raw, role_raw) = role_id_with_owner_components(s)?;
        let account = AccountId::parse_encoded(account_raw).map_err(|_| {
            iroha_model_base::error::ParseError::new("Invalid account component in RoleIdWithOwner")
        })?;
        let id = role_raw.parse().map_err(|_| {
            iroha_model_base::error::ParseError::new("Invalid role component in RoleIdWithOwner")
        })?;
        Ok(RoleIdWithOwner { account, id })
    }
}
impl norito::json::JsonKeyCodec for RoleIdWithOwner {
    fn encode_json_key(&self, out: &mut String) {
        norito::json::write_json_string(&self.to_string(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, norito::json::Error> {
        let (account_raw, role_raw) = role_id_with_owner_components(encoded)
            .map_err(|error| norito::json::Error::Message(error.to_string()))?;
        let account =
            <AccountId as norito::json::JsonObjectKeyOwned>::from_json_key_text(account_raw)
                .map_err(|error| {
                    if cfg!(all(test, sumeragi_model_mutation = "DM26"))
                        && matches!(
                            error,
                            norito::json::Error::ScopedDecodeResource(_)
                                | norito::json::Error::DecodeResource(_)
                        )
                    {
                        return norito::json::Error::Message(error.to_string());
                    }
                    error
                })?;
        let id = role_raw.parse().map_err(|_| {
            norito::json::Error::Message("Invalid role component in RoleIdWithOwner".into())
        })?;
        Ok(Self { account, id })
    }
}

#[cfg(test)]
mod native_assignment_tests {
    use super::*;
    #[test]
    fn role_assignment_storage_keys_preserve_original_account_refusal_and_retry() {
        use norito::core::{
            DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError,
            classify_decode_attempt,
        };
        use norito::json::JsonKeyCodec as _;
        let expected = RoleIdWithOwner::new(
            AccountId::new(
                iroha_crypto::KeyPair::from_seed(vec![42; 32], iroha_crypto::Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            ),
            "ordinary_mint_purpose".parse().unwrap(),
        );
        let literal = expected.to_string();
        let storage = mv::storage::Storage::<RoleIdWithOwner, ()>::new();
        {
            let mut block = storage.block();
            block.insert(expected.clone(), ());
            block.commit();
        }
        let wire = norito::json::to_json(&storage).unwrap();
        let source_pointer = wire.as_ptr();
        let decode = |mode| -> Result<(), norito::json::Error> {
            if mode == 0 {
                assert_eq!(RoleIdWithOwner::decode_json_key(&literal)?, expected);
            } else {
                let restored: mv::storage::Storage<RoleIdWithOwner, ()> =
                    norito::json::from_json(&wire)?;
                assert_eq!(restored.view().get(&expected), Some(&()));
            }
            Ok(())
        };
        let limits = |bytes| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let demands = [0, 1].map(|mode| {
            let (decoded, usage) =
                norito::core::with_decode_limits_measured(limits(usize::MAX), || decode(mode));
            decoded.expect("actual reader accepts the original canonical input");
            let demand = usage.total_allocated_bytes();
            assert!(demand > 0);
            demand
        });
        let context_limit = demands
            .iter()
            .try_fold(0_usize, |sum, demand| sum.checked_add(*demand))
            .unwrap()
            .checked_mul(2)
            .unwrap();
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original = DecodeBudgetContext::try_new_owned(limits(context_limit), &pool).unwrap();
        let baseline = pool.reserved_bytes();
        // This original pool owns decoder counters. Ordinary Storage/DTO graphs are
        // not claimed to have physical original-pool admission by this control.
        for (mode, demand) in demands.into_iter().enumerate() {
            let before = original.consumed_allocated_bytes();
            let mut observed = None;
            let refusal = original.with(|| norito::with_decode_limits_scope(
                limits(demand - 1), || classify_decode_attempt(|| {
                    let error = decode(mode).expect_err("one-byte-short original reader must refuse");
                    let norito::json::Error::ScopedDecodeResource(origin) = &error else {
                        panic!("Role assignment storage key must retain its original account scoped refusal: {error:?}");
                    };
                    observed = Some(origin.clone());
                    Err::<(), _>(error.into_core_error())
                }))).unwrap_err();
            assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
            let refusal = refusal.into_error();
            assert_eq!(
                refusal.decode_resource_error(),
                Some(DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(demand).unwrap(),
                    limit: u64::try_from(demand - 1).unwrap(),
                })
            );
            let norito::Error::ScopedDecodeResource(returned) = refusal else {
                panic!("reader must return its exact original observer");
            };
            assert_eq!(returned, observed.unwrap());
            drop(returned);
            assert_eq!(pool.reserved_bytes(), baseline);
            let after_refusal = original.consumed_allocated_bytes();
            // Outer counters debit the attempted final charge before the narrower
            // inner ceiling refuses. Retry reuses that same cumulative owner.
            assert_eq!(after_refusal - before, u64::try_from(demand).unwrap());
            original
                .with(|| decode(mode))
                .expect("same input and original context retry");
            assert_eq!(
                original.consumed_allocated_bytes() - after_refusal,
                u64::try_from(demand).unwrap()
            );
            assert_eq!(pool.reserved_bytes(), baseline);
            let (refusal, usage) =
                norito::core::with_decode_limits_measured(limits(demand - 1), || decode(mode));
            let error = refusal
                .expect_err("same input unscoped refusal")
                .into_core_error();
            assert_eq!(
                error.decode_resource_error(),
                Some(DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(demand).unwrap(),
                    limit: u64::try_from(demand - 1).unwrap(),
                })
            );
            assert!(!matches!(error, norito::Error::ScopedDecodeResource(_)));
            assert!(usage.total_allocated_bytes() < demand);
        }
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
        for invalid in [
            "no_separator".to_owned(),
            "alice@banka.dataspace|reader".to_owned(),
            format!("{}|bad#role", expected.account),
        ] {
            let error = RoleIdWithOwner::decode_json_key(&invalid).unwrap_err();
            assert!(error.into_core_error().decode_resource_error().is_none());
        }
        assert_eq!(literal.parse::<RoleIdWithOwner>().unwrap(), expected);
        assert_eq!(wire.as_ptr(), source_pointer);
        assert_eq!(storage.view().get(&expected), Some(&()));
    }

    #[test]
    fn sole_native_assignment_key_roundtrips_and_binds_account_and_role() {
        let account = AccountId::new(
            iroha_crypto::KeyPair::from_seed(vec![42; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let key = RoleIdWithOwner::new(account.clone(), "ordinary_mint_purpose".parse().unwrap());
        let raw = norito::encode_canonical(&key).unwrap();
        let decoded: RoleIdWithOwner = norito::decode_canonical(&raw).unwrap();
        assert_eq!(decoded, key);
        assert_eq!(key.to_string().parse::<RoleIdWithOwner>().unwrap(), key);
        let changed = RoleIdWithOwner::new(account, "other_role".parse().unwrap());
        assert_ne!(
            crate::sumeragi_finality::world_state_value_hash_v1(&key).unwrap(),
            crate::sumeragi_finality::world_state_value_hash_v1(&changed).unwrap()
        );
        assert!("no_separator".parse::<RoleIdWithOwner>().is_err());
    }

    #[test]
    fn native_assignment_keys_roundtrip_complete_role_names_containing_pipes() {
        use norito::json::JsonKeyCodec as _;
        let account = AccountId::new(
            iroha_crypto::KeyPair::try_from_seed(vec![42; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        );
        let storage = mv::storage::Storage::<RoleIdWithOwner, ()>::new();
        for role in ["reader|writer", "|reader", "reader|"] {
            let expected = RoleIdWithOwner::new(account.clone(), role.parse().unwrap());
            let literal = expected.to_string();
            assert_eq!(literal.parse::<RoleIdWithOwner>().unwrap(), expected);
            assert_eq!(
                RoleIdWithOwner::decode_json_key(&literal).unwrap(),
                expected
            );
            let mut key = String::new();
            expected.encode_json_key(&mut key);
            assert_eq!(norito::json::from_json::<String>(&key).unwrap(), literal);
            let frame = norito::encode_canonical(&expected).unwrap();
            assert_eq!(
                norito::decode_canonical::<RoleIdWithOwner>(&frame).unwrap(),
                expected
            );
            let mut block = storage.block();
            block.insert(expected, ());
            block.commit();
        }
        let wire = norito::json::to_json(&storage).unwrap();
        let restored: mv::storage::Storage<RoleIdWithOwner, ()> =
            norito::json::from_json(&wire).unwrap();
        for role in ["reader|writer", "|reader", "reader|"] {
            let expected = RoleIdWithOwner::new(account.clone(), role.parse().unwrap());
            assert_eq!(restored.view().get(&expected), Some(&()));
        }
    }
}
