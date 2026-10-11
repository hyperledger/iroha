//! Structures, traits and impls related to `Account`s.
pub use self::{
    model::*,
    recovery::{
        AccountRecoveryPolicy, AccountRecoveryPolicyError, AccountRecoveryRequest,
        AccountRecoveryStatus, RecoveryGuardian,
    },
    rekey::{
        AccountAlias, AccountAliasDomain, AccountRekeyRecord, AccountRekeyRecordError,
        AccountRekeyTransitionProvenance,
    },
};
pub use admission::{
    AccountAdmissionMode, AccountAdmissionPolicy, DEFAULT_MAX_IMPLICIT_ACCOUNT_CREATIONS_PER_TX,
};
use core::fmt;
use iroha_crypto::{Hash, PublicKey};
use iroha_data_model_derive::{IdEqOrdHash, model};
use iroha_primitives::json::Json;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{format, str::FromStr, string::String, vec::Vec};
pub mod address;
pub mod admission;
pub mod controller;
pub mod curve;

mod i105_json;
pub mod recovery;
pub mod rekey;
use crate::{
    HasMetadata, Identifiable, IntoKeyValue, Registered, Registrable,
    common::{Owned, Ref},
    nexus::UniversalAccountId,
};
pub use address::{AccountAddress, AccountAddressError, AccountAddressErrorCode};
pub use controller::{AccountController, MultisigMember, MultisigPolicy, MultisigPolicyError};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::{error::ParseError, name::Name};
#[model]
mod model {
    use super::*;
    use crate::account::rekey::AccountAlias;
    /// Canonical domainless account identity keyed only by the authorization controller.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_crypto::{Algorithm, KeyPair};
    /// use iroha_data_model::account::AccountId;
    ///
    /// let keypair = KeyPair::try_from_seed(vec![0xAB; 32], Algorithm::Ed25519)
    ///     .expect("valid fixture seed");
    /// let id = AccountId::new(keypair.public_key().clone());
    /// ```
    #[derive(Clone, IntoSchema, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::account::model::AccountId")]
    pub struct AccountId {
        /// Controller responsible for authorising account actions.
        pub controller: AccountController,
    }
    /// Account entity is an authority which is used to execute `Iroha Special Instructions`.
    #[derive(derive_more::Debug, Clone, IdEqOrdHash, Decode, Encode, IntoSchema)]
    #[allow(clippy::multiple_inherent_impl)]
    #[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize)]
    #[norito(no_fast_from_json)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::account::model::Account")]
    pub struct Account {
        /// Identification of the [`Account`].
        pub id: AccountId,
        /// Metadata of this account as a key-value store.
        pub metadata: Metadata,
        /// Stable alias under which the account is addressed (if provided).
        #[norito(required)]
        pub label: Option<AccountAlias>,
        /// Universal account identifier bound to this account (if registered in Nexus).
        #[norito(required)]
        pub uaid: Option<crate::nexus::UniversalAccountId>,
        /// Opaque identifiers bound to this account's UAID.
        pub opaque_ids: Vec<OpaqueAccountId>,
    }
    /// Builder submitted in a transaction to register a canonical domainless account.
    #[derive(derive_more::Debug, Clone, IdEqOrdHash, Decode, Encode, IntoSchema)]
    #[allow(clippy::multiple_inherent_impl)]
    #[derive(crate :: DeriveJsonSerialize)]
    #[norito(no_fast_from_json)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::account::model::NewAccount")]
    pub struct NewAccount {
        /// Canonical domainless account identity.
        pub id: AccountId,
        /// Metadata supplied during registration.
        pub metadata: Metadata,
        /// Stable alias under which the account is addressed (if provided).
        #[norito(required)]
        pub label: Option<AccountAlias>,
        /// Universal account identifier bound to this account (if registered in Nexus).
        #[norito(required)]
        pub uaid: Option<crate::nexus::UniversalAccountId>,
        /// Opaque identifiers bound to this account's UAID.
        pub opaque_ids: Vec<OpaqueAccountId>,
    }
}
/// Failure of the sole canonical I105 account text parser.
///
/// Resource errors retain their original fields and observer identity. Diagnostic codes are
/// projected only at a display or telemetry boundary; they grant no new admission provenance.
#[derive(Clone, Debug)]
pub enum AccountIdParseError {
    /// Text is not one exact canonical I105 account literal.
    InvalidFormat,
    /// Original failure of the canonical address/controller owner.
    Address(AccountAddressError),
}
impl AccountIdParseError {
    // One owning projection preserves an Address cause at every canonical parser
    // phase, including the final admitted controller transfer.
    fn from_address_error(error: AccountAddressError) -> Self {
        if cfg!(all(test, sumeragi_model_mutation = "DM22")) && error.is_decode_resource_limit() {
            return Self::Address(AccountAddressError::DecodeResourceLimit);
        }
        Self::Address(error)
    }

    /// Stable diagnostic label, without discarding the owned error.
    #[must_use]
    pub const fn code_str(&self) -> &'static str {
        match self {
            Self::InvalidFormat => ERR_ACCOUNT_LITERAL_FORMAT,
            Self::Address(error) => error.code_str(),
        }
    }
    /// Whether canonical account work was refused by its decode admission.
    #[must_use]
    pub const fn is_decode_resource_limit(&self) -> bool {
        matches!(self, Self::Address(error) if error.is_decode_resource_limit())
    }
}
impl fmt::Display for AccountIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_str())
    }
}
impl std::error::Error for AccountIdParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Address(error) => Some(error),
            Self::InvalidFormat => None,
        }
    }
}

impl PartialEq for AccountId {
    fn eq(&self, other: &Self) -> bool {
        self.controller == other.controller
    }
}
impl Eq for AccountId {}
impl PartialOrd for AccountId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for AccountId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.controller.cmp(&other.controller)
    }
}
impl core::hash::Hash for AccountId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.controller.hash(state);
    }
}

impl norito::json::FastJsonWrite for AccountId {
    fn write_json(&self, out: &mut String) {
        let literal = self
            .canonical_i105()
            .expect("AccountId JSON serialization requires canonical I105 encoding");
        norito::json::JsonSerialize::json_serialize(&literal, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        i105_json::write_bounded(self, out)
    }
}

impl norito::json::JsonDeserialize for AccountId {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        account_id_from_json_str(&value)
    }

    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        let norito::json::Value::String(value) = value else {
            return Err(invalid_account_id_json());
        };
        account_id_from_json_str(value)
    }
}

impl norito::json::JsonObjectKey for AccountId {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        let canonical = self
            .canonical_i105()
            .expect("AccountId JSON serialization requires canonical I105 encoding");
        visitor(&canonical)
    }

    fn visit_json_key_text_checked(
        &self,
        visitor: impl FnMut(&str) -> Result<(), norito::json::BoundedJsonError>,
    ) -> Result<(), norito::json::BoundedJsonError> {
        i105_json::visit_key_text(self, visitor)
    }
}

impl norito::json::JsonObjectKeyOwned for AccountId {
    fn from_json_key_text(key: &str) -> Result<Self, norito::json::Error> {
        account_id_from_json_str(key)
    }
}

fn account_id_from_json_str(value: &str) -> Result<AccountId, norito::json::Error> {
    reserve_account_literal_json_decode(value.len())?;
    AccountId::parse_encoded(value).map_err(|error| match error {
        AccountIdParseError::Address(error) if error.is_decode_resource_limit() => {
            address::map_account_address_json_error(error)
        }
        _ => invalid_account_id_json(),
    })
}

fn invalid_account_id_json() -> norito::json::Error {
    norito::json::Error::Message("invalid I105 account identifier".to_owned())
}

pub(super) fn reserve_account_literal_json_decode(
    raw_bytes: usize,
) -> Result<(), norito::json::Error> {
    // Source-derived raw-length upper bound for the canonical I105 parser. At its
    // phase maxima it can retain: one digit buffer (1S), radix work plus output
    // (3S), base32 checksum work (2S), canonical re-encode bytes/digits/output
    // (5S), original/keyed/dedup member topology (4S), and the three payload
    // families owned by address, AccountId, and sort keys (3S). Percent/base105
    // decoding only shrinks, and a valid member carries at least a 32-byte key,
    // which bounds its Vec/tuple topology by the four-S term. Rust Vec geometric
    // growth is covered by the doubled radix/re-encode terms.
    let components = [1_usize, 3, 2, 5, 4, 3];
    let bytes = components.into_iter().try_fold(0_usize, |total, units| {
        raw_bytes
            .checked_mul(units)
            .and_then(|component| total.checked_add(component))
    });
    let bytes = bytes.ok_or(norito::json::Error::DecodeResourceLimit)?;
    norito::core::reserve_decode_allocation(bytes)
        .map_err(norito::json::Error::from_decode_resource)
}

impl norito::json::JsonDeserialize for NewAccount {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use norito::json::MapVisitor;
        let mut visitor = MapVisitor::new(parser)?;
        let mut id: Option<AccountId> = None;
        let mut metadata: Option<Metadata> = None;
        let mut label: Option<Option<AccountAlias>> = None;
        let mut uaid: Option<Option<UniversalAccountId>> = None;
        let mut opaque_ids: Option<Vec<OpaqueAccountId>> = None;
        while let Some(key) = visitor.next_key()? {
            match key.as_str() {
                "id" => {
                    if id.is_some() {
                        return Err(norito::json::Error::duplicate_field("id"));
                    }
                    id = Some(visitor.parse_value::<AccountId>()?);
                }
                "metadata" => {
                    if metadata.is_some() {
                        return Err(norito::json::Error::duplicate_field("metadata"));
                    }
                    metadata = Some(visitor.parse_value::<Metadata>()?);
                }
                "label" => {
                    if label.is_some() {
                        return Err(norito::json::Error::duplicate_field("label"));
                    }
                    label = Some(visitor.parse_value::<Option<AccountAlias>>()?);
                }
                "uaid" => {
                    if uaid.is_some() {
                        return Err(norito::json::Error::duplicate_field("uaid"));
                    }
                    uaid = Some(visitor.parse_value::<Option<UniversalAccountId>>()?);
                }
                "opaque_ids" => {
                    if opaque_ids.is_some() {
                        return Err(norito::json::Error::duplicate_field("opaque_ids"));
                    }
                    opaque_ids = Some(visitor.parse_value::<Vec<OpaqueAccountId>>()?);
                }
                other => return Err(norito::json::Error::unknown_field(other.to_owned())),
            }
        }
        visitor.finish()?;
        let id = id.ok_or_else(|| norito::json::Error::missing_field("id"))?;
        Ok(Self {
            id,
            metadata: metadata.ok_or_else(|| norito::json::Error::missing_field("metadata"))?,
            label: label.ok_or_else(|| norito::json::Error::missing_field("label"))?,
            uaid: uaid.ok_or_else(|| norito::json::Error::missing_field("uaid"))?,
            opaque_ids: opaque_ids
                .ok_or_else(|| norito::json::Error::missing_field("opaque_ids"))?,
        })
    }
}
/// Opaque identifier that maps to a UAID without disclosing raw PII.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[repr(transparent)]
#[norito(decode_from_slice)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::OpaqueAccountId")]
pub struct OpaqueAccountId(Hash);
impl OpaqueAccountId {
    /// Construct an opaque identifier from a pre-hashed value.
    #[must_use]
    pub fn from_hash(hash: Hash) -> Self {
        Self(hash)
    }
    /// Borrow the underlying hash.
    #[must_use]
    pub fn as_hash(&self) -> &Hash {
        &self.0
    }
}
impl fmt::Display for OpaqueAccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "opaque:{}", self.0)
    }
}
impl From<Hash> for OpaqueAccountId {
    fn from(value: Hash) -> Self {
        Self::from_hash(value)
    }
}
impl From<OpaqueAccountId> for Hash {
    fn from(value: OpaqueAccountId) -> Self {
        value.0
    }
}
impl FromStr for OpaqueAccountId {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_literal = s.strip_prefix("opaque:").ok_or_else(|| {
            ParseError::new("opaque account id must use `opaque:<lowercase-hex>`")
        })?;
        if hex_literal.len() != Hash::LENGTH * 2
            || !hex_literal
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ParseError::new(
                "opaque account id must use `opaque:<lowercase-hex>`",
            ));
        }
        let opaque = Hash::from_str(hex_literal)
            .map(Self::from_hash)
            .map_err(|_| ParseError::new("opaque account id hash is invalid"))?;
        if opaque.to_string() != s {
            return Err(ParseError::new(
                "opaque account id must use `opaque:<lowercase-hex>`",
            ));
        }
        Ok(opaque)
    }
}

impl norito::SerializePayload for AccountId {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::SerializePayload::serialize(&self.controller, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(&self.controller)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(&self.controller)
    }
}

impl<'de> norito::DeserializePayload<'de> for AccountId {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("AccountId deserialization must succeed for valid archives")
    }
    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        let archived_controller = archived.cast::<AccountController>();
        norito::core::DeserializePayload::try_deserialize(archived_controller)
            .map(|controller| Self { controller })
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for AccountId {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (controller, used) = norito::core::decode_field_canonical::<AccountController>(bytes)?;
        Ok((Self { controller }, used))
    }
}
/// Read-only reference to [`Account`]. Used in query filters to avoid copying.
pub type AccountEntry<'world> = Ref<'world, AccountId, AccountValue>;
/// Canonical account data stored in the world state without duplicating the identifier.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::AccountDetails")]
pub struct AccountDetails {
    /// Arbitrary metadata attached to the account.
    pub metadata: Metadata,
    /// Stable alias referenced by rekey records.
    #[norito(required)]
    pub label: Option<rekey::AccountAlias>,
    /// Universal account identifier bound to this account, when applicable.
    #[norito(required)]
    pub uaid: Option<UniversalAccountId>,
    /// Opaque identifiers mapped to this account's UAID.
    pub opaque_ids: Vec<OpaqueAccountId>,
}
impl AccountDetails {
    /// Construct a new account details record.
    #[must_use]
    pub fn new(
        metadata: Metadata,
        label: Option<rekey::AccountAlias>,
        uaid: Option<UniversalAccountId>,
        opaque_ids: Vec<OpaqueAccountId>,
    ) -> Self {
        Self {
            metadata,
            label,
            uaid,
            opaque_ids,
        }
    }
    /// Get a reference to the attached metadata.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    /// Get a mutable reference to the attached metadata.
    #[must_use]
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }
    /// Insert a metadata key/value pair, returning the previous value if present.
    pub fn insert(&mut self, key: Name, value: Json) -> Option<Json> {
        self.metadata.insert(key, value)
    }
    /// Remove a metadata entry by key, returning the removed value if present.
    #[cfg(feature = "transparent_api")]
    pub fn remove(&mut self, key: &Name) -> Option<Json> {
        self.metadata.remove(key)
    }
    /// Borrow the stable account alias, if assigned.
    #[must_use]
    pub fn label(&self) -> Option<&rekey::AccountAlias> {
        self.label.as_ref()
    }
    /// Set or clear the stable account alias.
    pub fn set_label(&mut self, label: Option<rekey::AccountAlias>) {
        self.label = label;
    }
    /// Borrow the universal account identifier attached to this account.
    #[must_use]
    pub fn uaid(&self) -> Option<&UniversalAccountId> {
        self.uaid.as_ref()
    }
    /// Assign a universal account identifier to this record.
    pub fn set_uaid(&mut self, uaid: Option<UniversalAccountId>) {
        self.uaid = uaid;
    }
    /// Borrow the opaque identifiers bound to this account.
    #[must_use]
    pub fn opaque_ids(&self) -> &[OpaqueAccountId] {
        &self.opaque_ids
    }
    /// Replace the opaque identifiers bound to this account.
    pub fn set_opaque_ids(&mut self, opaque_ids: Vec<OpaqueAccountId>) {
        self.opaque_ids = opaque_ids;
    }
}
impl Default for AccountDetails {
    fn default() -> Self {
        Self::new(Metadata::default(), None, None, Vec::new())
    }
}
/// [`Account`] without `id`. Needed only for the world-state account map to reduce memory usage. In
/// other places use [`Account`] directly.
pub type AccountValue = Owned<AccountDetails>;
const ERR_ACCOUNT_LITERAL_FORMAT: &str = "AccountId must use a canonical I105 literal";
impl AccountId {
    /// Construct a single-signature account identifier.
    #[inline]
    #[must_use]
    pub fn new(signatory: PublicKey) -> Self {
        Self {
            controller: AccountController::single(signatory),
        }
    }
    /// Construct a multisignature account identifier.
    #[inline]
    #[must_use]
    pub fn new_multisig(policy: MultisigPolicy) -> Self {
        Self {
            controller: AccountController::multisig(policy),
        }
    }
    /// Convenience alias for [`Self::new`].
    #[inline]
    #[must_use]
    pub fn of(signatory: PublicKey) -> Self {
        Self::new(signatory)
    }
    /// Borrow the controller governing this account.
    #[inline]
    #[must_use]
    pub fn controller(&self) -> &AccountController {
        &self.controller
    }
    /// Visit each exact nested allocation made when this identifier is copied
    /// into an admitted retained owner, without allocating during the visit.
    ///
    /// # Errors
    /// Rejects malformed stored controller material or layout overflow.
    pub fn for_each_admission_clone_layout(
        &self,
        visit: impl FnMut(std::alloc::Layout),
    ) -> Result<(), norito::core::Error> {
        self.controller.for_each_admission_clone_layout(visit)
    }
    /// Fallibly clone this identifier for an independently prepaid owner.
    ///
    /// The caller must retain the exact nested layout charges reported by
    /// [`Self::for_each_admission_clone_layout`] until this clone is dropped.
    ///
    /// # Errors
    /// Rejects malformed stored controller material or a resource refusal.
    pub fn try_clone_for_admission(&self) -> Result<Self, norito::core::Error> {
        Ok(Self {
            controller: self.controller.try_clone_for_admission()?,
        })
    }
    /// Borrow this account identifier.
    #[inline]
    #[must_use]
    pub fn account(&self) -> &Self {
        self
    }
    /// Return the canonical subject identity for this account.
    #[inline]
    #[must_use]
    pub fn subject_id(&self) -> Self {
        self.clone()
    }
    /// Borrow the single-signature public key when present.
    #[inline]
    #[must_use]
    pub fn try_signatory(&self) -> Option<&PublicKey> {
        self.controller.single_signatory()
    }
    /// Replace the account signatory, converting the controller to single-key.
    #[inline]
    pub fn set_signatory(&mut self, signatory: PublicKey) {
        self.controller = AccountController::single(signatory);
    }
    /// Wipe controller key bytes before discarding a confidential account copy.
    ///
    /// The identifier intentionally becomes invalid and must not be used after
    /// this call. It is reserved for decrypted restricted payload containers.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.controller.zeroize_for_confidential_discard();
    }
    /// Borrow the single-signature public key, panicking if the controller is not single-key.
    #[inline]
    #[must_use]
    pub fn expect_single_signatory(&self) -> &PublicKey {
        self.controller
            .single_signatory()
            .expect("account controller is not single-key")
    }
    /// Borrow the multisignature policy when configured.
    #[inline]
    #[must_use]
    pub fn multisig_policy(&self) -> Option<&MultisigPolicy> {
        self.controller.multisig_policy()
    }
    /// Return `true` if the account signatory matches the given `public_key`.
    #[inline]
    #[cfg(feature = "transparent_api")]
    pub fn signatory_matches(&self, public_key: &PublicKey) -> bool {
        self.try_signatory().is_some_and(|pk| pk == public_key)
    }
    /// Construct the address payload used for canonical I105 encoding.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if the account identifier cannot be encoded
    /// into an [`AccountAddress`] (for example, when the controller configuration lacks support).
    #[inline]
    pub fn to_account_address(&self) -> Result<AccountAddress, AccountAddressError> {
        AccountAddress::from_account_id(self)
    }
    /// Encode the account as an i105 string for the provided network prefix.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if the account cannot be encoded or if i105
    /// conversion fails for the provided network prefix.
    #[inline]
    pub fn to_i105_for_discriminant(
        &self,
        network_prefix: u16,
    ) -> Result<String, AccountAddressError> {
        AccountAddress::retained_account_i105(self, network_prefix)
    }
    /// Encode the account as canonical I105 using the configured chain discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] when address encoding fails.
    ///
    /// The literal is derived for each call rather than retained in a process-wide cache. Account
    /// controllers are externally supplied and can be large, so caching both their encoded keys and
    /// rendered literals would turn a bounded request into persistent memory growth.
    /// Output borrows retained keys and does not cross an inbound decoder admission boundary.
    #[inline]
    pub fn canonical_i105(&self) -> Result<String, AccountAddressError> {
        let prefix = address::chain_discriminant();
        self.to_i105_for_discriminant(prefix)
    }
    /// Encode the account as canonical lowercase hexadecimal.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] when canonical payload construction fails.
    #[inline]
    pub fn to_canonical_hex(&self) -> Result<String, AccountAddressError> {
        AccountAddress::retained_account_hex(self)
    }
    /// Parse a canonical I105 account identifier from text.
    ///
    /// Canonical I105 literals are accepted.
    /// Domain-qualified identifiers, canonical hex, dotted or non-canonical I105 literals,
    /// aliases, UAIDs, opaque account literals, and non-I105 envelopes are rejected.
    ///
    /// # Errors
    ///
    /// Preserves original decoder resource refusals; invalid formats retain their diagnostic code.
    pub fn parse_encoded(input: &str) -> Result<Self, AccountIdParseError> {
        if input.is_empty() || input.trim() != input || input.contains('@') {
            return Err(AccountIdParseError::InvalidFormat);
        }
        let expected_prefix = address::chain_discriminant();
        let address = AccountAddress::from_i105_for_discriminant(input, Some(expected_prefix))
            .map_err(|error| match error {
                AccountAddressError::MissingI105Sentinel
                | AccountAddressError::I105TooShort
                | AccountAddressError::InvalidI105Char(_)
                | AccountAddressError::InvalidI105Base
                | AccountAddressError::InvalidI105Digit(_)
                | AccountAddressError::UnsupportedAddressFormat
                | AccountAddressError::InvalidLength => AccountIdParseError::InvalidFormat,
                error => AccountIdParseError::from_address_error(error),
            })?;
        let canonical = address
            .to_i105_for_discriminant(expected_prefix)
            .map_err(AccountIdParseError::from_address_error)?;
        if canonical != input {
            return Err(AccountIdParseError::InvalidFormat);
        }
        let controller = address
            .to_account_controller()
            .map_err(AccountIdParseError::from_address_error)?;
        Ok(Self { controller })
    }
    /// Canonicalise a textual identifier into the i105 form.
    ///
    /// # Errors
    /// Preserves the canonical parser's original error and any output refusal.
    pub fn canonicalize(input: &str) -> Result<String, AccountIdParseError> {
        Self::parse_encoded(input)?
            .canonical_i105()
            .map_err(AccountIdParseError::from_address_error)
    }
}
impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i105 = self.canonical_i105().map_err(|_| fmt::Error)?;
        f.write_str(&i105)
    }
}
impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
const _: fn() = || {
    fn assert_decode<'a, T: norito::core::DecodeFromSlice<'a>>() {}
    fn assert_account() {
        assert_decode::<AccountId>();
    }
    let _ = assert_account;
};
impl Account {
    /// Construct a registration builder for a canonical domainless account.
    #[inline]
    #[must_use]
    pub fn new(id: AccountId) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id)
    }
    /// Borrow the account signatory when present.
    #[inline]
    #[must_use]
    pub fn try_signatory(&self) -> Option<&PublicKey> {
        self.id.try_signatory()
    }
    /// Return the account signatory, panicking if the controller is not single-key.
    ///
    /// Prefer [`Self::try_signatory`] whenever the controller can originate from
    /// decoded input or mutable state.
    #[inline]
    #[must_use]
    pub fn expect_single_signatory(&self) -> &PublicKey {
        self.id.expect_single_signatory()
    }
    /// Return the controller governing this account.
    #[inline]
    #[must_use]
    pub fn controller(&self) -> &AccountController {
        self.id.controller()
    }
    /// Borrow the canonical account alias, if one is assigned.
    #[inline]
    #[must_use]
    pub fn label(&self) -> Option<&rekey::AccountAlias> {
        self.label.as_ref()
    }
    /// Borrow the universal account identifier, if assigned.
    #[inline]
    #[must_use]
    pub fn uaid(&self) -> Option<&UniversalAccountId> {
        self.uaid.as_ref()
    }
    /// Borrow the opaque identifiers bound to this account.
    #[inline]
    #[must_use]
    pub fn opaque_ids(&self) -> &[OpaqueAccountId] {
        &self.opaque_ids
    }
}
#[cfg(feature = "transparent_api")]
impl NewAccount {
    /// Convert into [`Account`].
    pub fn into_account(self) -> Account {
        Account {
            id: self.id,
            metadata: self.metadata,
            label: self.label,
            uaid: self.uaid,
            opaque_ids: self.opaque_ids,
        }
    }
}
impl NewAccount {
    /// Create a registration builder for a canonical domainless account.
    #[must_use]
    pub fn new(id: AccountId) -> Self {
        Self {
            id,
            metadata: Metadata::default(),
            label: None,
            uaid: None,
            opaque_ids: Vec::new(),
        }
    }
    /// Replace metadata on this builder.
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
    /// Assign or replace the stable alias on this builder.
    #[must_use]
    pub fn with_label(mut self, label: Option<rekey::AccountAlias>) -> Self {
        self.label = label;
        self
    }
    /// Assign or clear the bound UAID on this builder.
    #[must_use]
    pub fn with_uaid(mut self, uaid: Option<UniversalAccountId>) -> Self {
        self.uaid = uaid;
        self
    }
    /// Replace the opaque identifier set on this builder.
    #[must_use]
    pub fn with_opaque_ids(mut self, opaque_ids: Vec<OpaqueAccountId>) -> Self {
        self.opaque_ids = opaque_ids;
        self
    }
    /// Remove the label assigned to this builder, if any.
    #[must_use]
    pub fn without_label(mut self) -> Self {
        self.label = None;
        self
    }
    /// Borrow the currently assigned alias on the builder.
    #[must_use]
    pub fn label(&self) -> Option<&rekey::AccountAlias> {
        self.label.as_ref()
    }
    /// Borrow the universal account identifier assigned on the builder, if any.
    #[must_use]
    pub fn uaid(&self) -> Option<&UniversalAccountId> {
        self.uaid.as_ref()
    }
    /// Borrow the opaque identifiers assigned on the builder.
    #[must_use]
    pub fn opaque_ids(&self) -> &[OpaqueAccountId] {
        &self.opaque_ids
    }
}
impl HasMetadata for NewAccount {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}
impl HasMetadata for Account {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}
impl Registered for Account {
    type With = NewAccount;
}
impl Registrable for NewAccount {
    type Target = Account;
    fn build(self, _authority: &AccountId) -> Self::Target {
        Self::Target {
            id: self.id,
            metadata: self.metadata,
            label: self.label,
            uaid: self.uaid,
            opaque_ids: self.opaque_ids,
        }
    }
}
impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let controller_desc = match self.controller() {
            AccountController::Single(signatory) => signatory.to_string(),
            AccountController::Multisig(policy) => format!(
                "multisig(threshold={}, members={})",
                policy.threshold(),
                policy.members().len()
            ),
        };
        write!(
            f,
            "Account{{id: {}, controller: {controller_desc}}}",
            self.id
        )
    }
}
impl fmt::Display for NewAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}
#[cfg(test)]
mod account_id_parsing_tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::domain::DomainId;
    use norito::{core::decode_from_bytes, to_bytes};
    fn guard_chain_discriminant() -> address::ChainDiscriminantGuard {
        address::ChainDiscriminantGuard::enter(address::chain_discriminant())
    }
    fn checked_keypair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked account fixture keypair")
    }
    #[test]
    fn from_str_rejects_public_key_addresses() {
        let public_key: PublicKey =
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .expect("parse public key literal");
        let raw = format!("{public_key}@banka.dataspace");
        let err = AccountId::parse_encoded(&raw)
            .expect_err("public_key@domain literals must be rejected");
        assert!(
            err.code_str().to_ascii_lowercase().contains("i105"),
            "unexpected error: {}",
            err.code_str()
        );
    }
    #[test]
    fn from_str_rejects_canonical_hex_addresses_without_domain() {
        let key_pair = checked_keypair(0xBC);
        let account = AccountId::new(key_pair.public_key().clone());
        let canonical = account.to_canonical_hex().expect("canonical hex encoding");
        let err = AccountId::parse_encoded(&canonical)
            .expect_err("canonical hex account literals must be rejected");
        assert!(
            err.code_str().to_ascii_lowercase().contains("i105"),
            "unexpected error: {}",
            err.code_str()
        );
    }
    #[test]
    fn encoded_literals_with_domain_are_rejected() {
        let _chain_guard = guard_chain_discriminant();
        let domain: DomainId =
            DomainId::try_new("fallback-domain", "universal").expect("valid domain");
        let key_pair = checked_keypair(0x5A);
        let account = AccountId::new(key_pair.public_key().clone());
        let address = AccountAddress::from_account_id(&account).expect("address encodes");
        let i105 = address
            .to_i105_for_discriminant(address::chain_discriminant())
            .expect("i105 encode");
        let canonical_hex = address.canonical_hex().expect("canonical hex encode");
        let domain_suffix = domain.to_string();
        for literal in [
            format!("{i105}@{domain_suffix}"),
            format!("{canonical_hex}@{domain_suffix}"),
        ] {
            let err = AccountId::parse_encoded(&literal)
                .expect_err("encoded literals with @domain suffix must be rejected");
            assert!(
                err.code_str().to_ascii_lowercase().contains("i105"),
                "unexpected error: {}",
                err.code_str()
            );
        }
    }
    #[test]
    fn from_str_rejects_alias_literals() {
        let err = AccountId::parse_encoded("blue-alias@banka.dataspace")
            .expect_err("aliases must be rejected");
        assert!(
            err.code_str().to_ascii_lowercase().contains("i105"),
            "unexpected error: {}",
            err.code_str()
        );
    }
    #[test]
    fn from_str_rejects_i105_alphabet_alias() {
        let alias_label = "primary";
        let err = AccountAddress::parse_encoded(alias_label, Some(address::chain_discriminant()))
            .expect_err("alias label should not parse as a valid address");
        assert_eq!(err.code_str(), "ERR_UNSUPPORTED_ADDRESS_FORMAT");
        let err = AccountId::parse_encoded("primary@banka.dataspace")
            .expect_err("aliases must be rejected");
        assert!(
            err.code_str().to_ascii_lowercase().contains("i105"),
            "unexpected error: {}",
            err.code_str()
        );
    }
    #[test]
    fn from_str_rejects_alias_domain_mismatch() {
        let err = AccountId::parse_encoded("blue-alias@otherland")
            .expect_err("mismatched alias domain must fail");
        assert!(
            err.code_str().to_ascii_lowercase().contains("i105"),
            "unexpected error message: {}",
            err.code_str()
        );
    }
    #[test]
    fn parse_returns_canonical_account_id() {
        let _guard = guard_chain_discriminant();
        let key_pair = checked_keypair(0xCD);
        let account = AccountId::new(key_pair.public_key().clone());
        let address = AccountAddress::from_account_id(&account).expect("account encodes");
        let i105 = address
            .to_i105_for_discriminant(address::chain_discriminant())
            .expect("i105 encode");
        let parsed = AccountId::parse_encoded(&i105).expect("i105 account id must parse");
        assert_eq!(parsed, account);
        assert_eq!(parsed.to_string(), i105);
    }
    #[test]
    fn parse_rejects_fullwidth_sentinel_i105_literal() {
        let _guard = guard_chain_discriminant();
        let key_pair = checked_keypair(0xA5);
        let account = AccountId::new(key_pair.public_key().clone());
        let canonical = account.to_string();
        let noncanonical = canonical.replacen("sora", "ｓｏｒａ", 1);
        let err = AccountId::parse_encoded(&noncanonical)
            .expect_err("fullwidth sentinel literal must be rejected");
        assert_eq!(err.code_str(), ERR_ACCOUNT_LITERAL_FORMAT);
    }
    #[test]
    fn parse_rejects_public_key_source() {
        let _guard = guard_chain_discriminant();
        let public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
        let raw = format!("{public_key}@banka.dataspace");
        let err = AccountId::parse_encoded(&raw).expect_err("public key source must be rejected");
        assert!(
            err.code_str().to_ascii_lowercase().contains("i105"),
            "unexpected error: {}",
            err.code_str()
        );
    }
    #[test]
    fn encoded_literals_roundtrip_without_domain_context() {
        let _guard_chain = guard_chain_discriminant();
        let key_pair = checked_keypair(0xEF);
        let account = AccountId::new(key_pair.public_key().clone());
        let address = AccountAddress::from_account_id(&account).expect("account encodes");
        let i105 = address
            .to_i105_for_discriminant(address::chain_discriminant())
            .expect("i105 encode");
        let literal = i105;
        let parsed = AccountId::parse_encoded(&literal).expect("encoded literal should parse");
        assert_eq!(parsed, account);
        assert_eq!(parsed.to_string(), literal);
    }
    #[test]
    fn parse_encoded_rejects_padded_i105_literal() {
        let _guard = guard_chain_discriminant();
        let key_pair = checked_keypair(0xEE);
        let account = AccountId::new(key_pair.public_key().clone());
        let literal = account.canonical_i105().expect("i105 encode");
        let padded = format!(" \n{literal}\t ");
        let err = AccountId::parse_encoded(&padded)
            .expect_err("padded i105 is not the canonical first-release literal");
        assert_eq!(err.code_str(), ERR_ACCOUNT_LITERAL_FORMAT);
    }
    #[test]
    fn norito_roundtrip_account_id() {
        let key_pair = checked_keypair(0xEF);
        let account = AccountId::new(key_pair.public_key().clone());
        let framed = to_bytes(&account).expect("encode account id");
        let decoded = decode_from_bytes::<AccountId>(&framed).expect("decode account id");
        assert_eq!(decoded, account);
    }
    #[test]
    fn parse_rejects_alias_source() {
        let _chain_guard = address::ChainDiscriminantGuard::enter(42);
        let err = AccountId::parse_encoded("blue-alias@banka.dataspace")
            .expect_err("alias must be rejected");
        assert!(
            err.code_str().to_ascii_lowercase().contains("i105"),
            "unexpected error: {}",
            err.code_str()
        );
    }
    #[test]
    fn canonicalize_rejects_canonical_hex_input() {
        let _guard = guard_chain_discriminant();
        let key_pair = checked_keypair(0xBC);
        let account = AccountId::new(key_pair.public_key().clone());
        let literal = account
            .to_canonical_hex()
            .expect("canonical hex literal must be available");
        let err =
            AccountId::canonicalize(&literal).expect_err("canonical hex input must be rejected");
        assert!(
            err.code_str().to_ascii_lowercase().contains("i105"),
            "unexpected error: {}",
            err.code_str()
        );
    }
    #[test]
    fn canonicalize_accepts_configured_i105_discriminant() {
        let _guard = address::ChainDiscriminantGuard::enter(42);
        let key_pair = checked_keypair(0xBD);
        let account = AccountId::new(key_pair.public_key().clone());
        let literal = account
            .to_i105_for_discriminant(42)
            .expect("configured i105 literal");
        let canonical = AccountId::canonicalize(&literal)
            .expect("canonicalize should accept the configured discriminant");
        assert_eq!(canonical, literal);
    }
    #[test]
    fn from_str_rejects_mismatched_i105_discriminant() {
        let _guard = address::ChainDiscriminantGuard::enter(42);
        let key_pair = checked_keypair(0xAA);
        let account = AccountId::new(key_pair.public_key().clone());
        let payload =
            address::AccountAddress::from_account_id(&account).expect("address encoding succeeds");
        let literal = payload
            .to_i105_for_discriminant(41)
            .expect("encode i105 with foreign prefix");
        let err = AccountId::parse_encoded(&literal).expect_err("prefix mismatch must fail");
        assert!(
            err.code_str()
                .contains(AccountAddressErrorCode::UnexpectedNetworkPrefix.as_str()),
            "expected ERR_UNEXPECTED_NETWORK_PREFIX, got {}",
            err.code_str()
        );
    }
    #[test]
    fn from_str_accepts_configured_i105_discriminant() {
        let _guard = address::ChainDiscriminantGuard::enter(7);
        let key_pair = checked_keypair(0xBB);
        let account = AccountId::new(key_pair.public_key().clone());
        let payload =
            address::AccountAddress::from_account_id(&account).expect("address encoding succeeds");
        let literal = payload
            .to_i105_for_discriminant(7)
            .expect("encode i105 with configured prefix");
        let parsed = AccountId::parse_encoded(&literal).expect("matching prefix should parse");
        assert_eq!(
            parsed.expect_single_signatory(),
            account.expect_single_signatory()
        );
    }
    #[test]
    fn from_str_rejects_encoded_address_with_domain_suffix() {
        let _guard = guard_chain_discriminant();
        let domain: DomainId = DomainId::try_new("wonderland", "universal").expect("valid domain");
        let key_pair = checked_keypair(0xBC);
        let account = AccountId::new(key_pair.public_key().clone());
        let payload =
            address::AccountAddress::from_account_id(&account).expect("address encoding succeeds");
        let literal = format!(
            "{}@{}",
            payload
                .to_i105_for_discriminant(address::chain_discriminant())
                .expect("encode i105"),
            domain
        );
        let err = AccountId::parse_encoded(&literal)
            .expect_err("encoded address with domain should be rejected");
        assert!(
            err.code_str().to_ascii_lowercase().contains("i105"),
            "unexpected error: {}",
            err.code_str()
        );
    }
    #[test]
    fn display_uses_chain_discriminant_sentinel() {
        let _guard = address::ChainDiscriminantGuard::enter(73);
        let key_pair = checked_keypair(0xCC);
        let account = AccountId::new(key_pair.public_key().clone());
        let rendered = account.to_string();
        let parsed =
            AccountAddress::parse_encoded(&rendered, None).expect("display should parse as i105");
        assert_eq!(
            parsed.to_account_id().expect("decode account id"),
            account,
            "rendered address should roundtrip to the same account"
        );
    }
    #[test]
    fn canonical_i105_is_chain_discriminant_scoped() {
        let key_pair = checked_keypair(0xCD);
        let account = AccountId::new(key_pair.public_key().clone());
        let first = {
            let _guard = address::ChainDiscriminantGuard::enter(73);
            let encoded = account.canonical_i105().expect("encode i105");
            assert_eq!(encoded, account.canonical_i105().expect("repeat i105"));
            encoded
        };
        let second = {
            let _guard = address::ChainDiscriminantGuard::enter(74);
            account.canonical_i105().expect("encode i105")
        };
        assert_ne!(
            first, second,
            "canonical I105 must include the active chain discriminant"
        );
    }
}
impl IntoKeyValue for Account {
    type Key = AccountId;
    type Value = AccountValue;
    fn into_key_value(self) -> (Self::Key, Self::Value) {
        let details = AccountDetails::new(self.metadata, self.label, self.uaid, self.opaque_ids);
        (self.id, Owned::new(details))
    }
}
/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Account, AccountAddress, AccountAdmissionMode, AccountAdmissionPolicy, AccountAlias,
        AccountAliasDomain, AccountController, AccountEntry, AccountId, AccountRecoveryPolicy,
        AccountRecoveryPolicyError, AccountRecoveryRequest, AccountRecoveryStatus,
        AccountRekeyRecord, AccountRekeyRecordError, AccountRekeyTransitionProvenance,
        AccountValue, MultisigMember, MultisigPolicy, NewAccount, OpaqueAccountId,
        RecoveryGuardian,
    };
}
#[cfg(test)]
#[cfg(feature = "transparent_api")]
mod tests {
    #[test]
    fn canonical_registry_schema_identity_roundtrips() {
        let value = OpaqueAccountId::from_hash(Hash::new(b"opaque-state-key"));
        assert_eq!(
            <OpaqueAccountId as norito::NoritoSchema>::nominal_name(),
            "iroha_data_model::account::OpaqueAccountId"
        );
        let encoded = norito::encode_canonical(&value).expect("canonical owner frame");
        assert_eq!(
            encoded[6..22],
            norito::schema::identity::frame_hash::<OpaqueAccountId>()
        );
        assert_eq!(
            norito::decode_canonical::<OpaqueAccountId>(&encoded)
                .expect("canonical owner roundtrip"),
            value
        );
        let mut wrong_owner = encoded;
        wrong_owner[6] ^= 1;
        assert!(matches!(
            norito::decode_canonical::<OpaqueAccountId>(&wrong_owner),
            Err(norito::Error::SchemaMismatch)
        ));
    }

    use super::*;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_model_base::name::Name;
    use iroha_model_base::topology::DataSpaceId;
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked account fixture keypair")
    }
    fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .expect("generate checked account fixture keypair")
    }
    #[test]
    fn admission_clone_layouts_match_single_and_multisig_retained_owners() {
        use std::alloc::Layout;

        let first = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
        let second = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
        let single = AccountId::new(first.public_key().clone());
        let mut layouts = Vec::new();
        single
            .for_each_admission_clone_layout(|layout| layouts.push(layout))
            .unwrap();
        assert_eq!(layouts, [Layout::array::<u8>(33).unwrap()]);
        assert_eq!(single.try_clone_for_admission().unwrap(), single);

        let multisig = AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                vec![
                    MultisigMember::new(first.public_key().clone(), 1).unwrap(),
                    MultisigMember::new(second.public_key().clone(), 1).unwrap(),
                ],
            )
            .unwrap(),
        );
        layouts.clear();
        multisig
            .for_each_admission_clone_layout(|layout| layouts.push(layout))
            .unwrap();
        assert_eq!(layouts.len(), 3);
        assert_eq!(layouts[0], Layout::array::<MultisigMember>(2).unwrap());
        assert_eq!(layouts[1], Layout::array::<u8>(33).unwrap());
        assert_eq!(layouts[2], Layout::array::<u8>(33).unwrap());
        assert_eq!(multisig.try_clone_for_admission().unwrap(), multisig);
    }
    #[test]
    fn parse_account_id() {
        let key_pair = checked_random_keypair();
        let account_id = AccountId::new(key_pair.public_key().clone());
        let literal = account_id.to_string();
        let parsed = AccountId::parse_encoded(&literal).expect("should be valid");
        assert_eq!(parsed.controller(), account_id.controller());
        assert_eq!(parsed.expect_single_signatory(), key_pair.public_key());
        let _err_empty_address =
            AccountId::parse_encoded("@domain").expect_err("@domain should not be valid");
        let _err_empty_domain = AccountId::parse_encoded(&format!("{literal}@"))
            .expect_err("address@ should not be valid");
        let _err_violates_format = AccountId::parse_encoded(&format!("{literal}#domain"))
            .expect_err("address#domain should not be valid");
    }
    #[test]
    fn account_single_signatory_exposed_explicitly() {
        let key_pair = checked_random_keypair();
        let public_key = key_pair.public_key().clone();
        let account_id = AccountId::new(public_key.clone());
        let account = Account::new(account_id.clone()).build(&account_id);
        assert_eq!(account.expect_single_signatory(), &public_key);
    }
    #[test]
    fn display_renders_i105_for_secp256k1() {
        let kp = checked_random_keypair_with_algorithm(Algorithm::Secp256k1);
        let account_id = AccountId::new(kp.public_key().clone());
        let rendered = account_id.to_string();
        let parsed = AccountId::parse_encoded(&rendered).expect("rendered i105 must parse");
        assert_eq!(
            parsed.expect_single_signatory(),
            account_id.expect_single_signatory()
        );
    }
    #[test]
    fn rekey_record_uses_account_alias() {
        let key_pair = checked_random_keypair();
        let signatory = key_pair.public_key().clone();
        let account_id = AccountId::new(signatory.clone());
        let label = rekey::AccountAlias::new(
            "alice".parse::<Name>().expect("valid label"),
            Some(rekey::AccountAliasDomain::new(
                "wonderland".parse::<Name>().expect("alias domain"),
            )),
            DataSpaceId::UNIVERSAL,
        );
        let account = Account {
            id: account_id.clone(),
            metadata: Metadata::default(),
            label: Some(label.clone()),
            uaid: None,
            opaque_ids: Vec::new(),
        };
        let record =
            rekey::AccountRekeyRecord::from_account(&account).expect("label must be present");
        assert_eq!(record.label, label);
        assert_eq!(record.active_account_id, account_id);
        assert_eq!(record.active_signatory, Some(signatory));
        assert!(record.previous_account_ids.is_empty());
        assert!(record.previous_signatories.is_empty());
    }
    #[test]
    fn rekey_record_absent_without_label() {
        let key_pair = checked_random_keypair();
        let account_id = AccountId::new(key_pair.public_key().clone());
        let account = Account {
            id: account_id,
            metadata: Metadata::default(),
            label: None,
            uaid: None,
            opaque_ids: Vec::new(),
        };
        assert!(rekey::AccountRekeyRecord::from_account(&account).is_none());
    }
    #[test]
    fn multisig_account_exposes_no_primary_signatory() {
        let members = vec![
            MultisigMember::new(checked_random_keypair().public_key().clone(), 1).expect("member"),
            MultisigMember::new(checked_random_keypair().public_key().clone(), 1).expect("member"),
        ];
        let policy = MultisigPolicy::new(2, members).expect("policy");
        let account_id = AccountId::new_multisig(policy);
        assert!(account_id.try_signatory().is_none());
        let account = Account {
            id: account_id.clone(),
            metadata: Metadata::default(),
            label: Some(rekey::AccountAlias::new(
                "vault".parse::<Name>().expect("label"),
                Some(rekey::AccountAliasDomain::new(
                    "wonderland".parse::<Name>().expect("alias domain"),
                )),
                DataSpaceId::UNIVERSAL,
            )),
            uaid: None,
            opaque_ids: Vec::new(),
        };
        assert!(account.try_signatory().is_none());
        let record = rekey::AccountRekeyRecord::from_account(&account).expect("record");
        assert_eq!(record.active_account_id, account_id);
        assert!(record.active_signatory.is_none());
        assert!(record.previous_account_ids.is_empty());
        assert!(record.previous_signatories.is_empty());
    }
    #[test]
    fn multisig_account_id_roundtrip() {
        let members = vec![
            MultisigMember::new(checked_random_keypair().public_key().clone(), 1).expect("member"),
            MultisigMember::new(checked_random_keypair().public_key().clone(), 2).expect("member"),
        ];
        let policy = MultisigPolicy::new(2, members).expect("policy");
        let account_id = AccountId::new_multisig(policy.clone());
        let literal = account_id
            .canonical_i105()
            .expect("i105 encoding should succeed");
        let parsed = AccountId::parse_encoded(&literal).expect("should parse multisig");
        let parsed_policy = parsed
            .multisig_policy()
            .expect("multisig policy should be present");
        assert_eq!(parsed_policy, &policy);
        assert!(parsed.try_signatory().is_none());
    }
    #[test]
    fn account_subject_id_is_domainless() {
        let key_pair = checked_random_keypair();
        let account = AccountId::new(key_pair.public_key().clone());
        assert_eq!(account.subject_id(), account);
    }
    #[test]
    fn account_accessor_returns_self() {
        let key_pair = checked_random_keypair();
        let account = AccountId::new(key_pair.public_key().clone());
        assert_eq!(account.account(), &account);
    }
    #[test]
    fn i105_checksum_failure_reports_error_code() {
        // Negative vector from fixtures/account/address_vectors.json (`i105-checksum-mismatch`).
        let literal = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSｱ";
        let err = AccountId::parse_encoded(literal).expect_err("invalid i105 payload must fail");
        assert_eq!(
            err.code_str(),
            AccountAddressErrorCode::ChecksumMismatch.as_str()
        );
    }
    #[test]
    fn account_builder_carries_uaid_into_details() {
        let key_pair = checked_random_keypair();
        let account_id = AccountId::new(key_pair.public_key().clone());
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::builder"));
        let opaque_id = OpaqueAccountId::from_hash(Hash::new(b"opaque::builder"));
        let new_account = Account::new(account_id.clone())
            .with_uaid(Some(uaid))
            .with_opaque_ids(vec![opaque_id]);
        assert_eq!(new_account.uaid(), Some(&uaid));
        assert_eq!(new_account.opaque_ids(), &[opaque_id]);
        let account = new_account.build(&account_id);
        assert_eq!(account.uaid(), Some(&uaid));
        let (stored_id, stored_value) = account.clone().into_key_value();
        assert_eq!(stored_id, account_id);
        let mut details = stored_value.into_inner();
        assert_eq!(details.uaid(), Some(&uaid));
        details.set_uaid(None);
        assert!(details.uaid().is_none());
    }
    #[test]
    fn domainless_account_builder_roundtrips_without_domain_state() {
        let key_pair = checked_random_keypair();
        let account_id = AccountId::new(key_pair.public_key().clone());
        let account = Account::new(account_id.clone()).build(&account_id);
        assert_eq!(account.id, account_id);
        let new_account = NewAccount::new(account_id.clone());
        assert_eq!(new_account.to_string(), account_id.to_string());
        assert_eq!(new_account.build(&account_id).id, account_id);
    }
}
#[cfg(test)]
mod json_tests {
    use super::*;
    use crate::{account::address, nexus::UniversalAccountId, prelude::Register};
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use iroha_model_base::topology::DataSpaceId;
    use norito::codec::{decode_adaptive, encode_adaptive};
    fn guard_chain_discriminant() -> address::ChainDiscriminantGuard {
        address::ChainDiscriminantGuard::enter(address::chain_discriminant())
    }
    fn checked_keypair_from_seed(seed: Vec<u8>) -> KeyPair {
        KeyPair::try_from_seed(seed, Algorithm::Ed25519)
            .expect("derive checked account JSON fixture keypair")
    }
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked account JSON fixture keypair")
    }
    #[test]
    fn account_json_roundtrip() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let account = Account {
            id,
            metadata: Metadata::default(),
            label: None,
            uaid: None,
            opaque_ids: Vec::new(),
        };
        let json = norito::json::to_json(&account).expect("serialize account");
        let decoded: Account = norito::json::from_json(&json).expect("deserialize account");
        assert_eq!(decoded, account);
    }
    #[test]
    fn opaque_account_id_from_str_accepts_only_canonical_literal() {
        let opaque = OpaqueAccountId::from_hash(Hash::new(b"opaque-account-id"));
        let canonical = opaque.to_string();
        assert_eq!(
            canonical
                .parse::<OpaqueAccountId>()
                .expect("canonical opaque account id"),
            opaque
        );
        let hex = opaque.as_hash().to_string();
        for literal in [
            hex.clone(),
            format!("OPAQUE:{hex}"),
            format!("opaque:{}", hex.to_uppercase()),
            format!(" opaque:{hex}"),
            format!("opaque:{hex} "),
        ] {
            assert!(
                literal.parse::<OpaqueAccountId>().is_err(),
                "noncanonical opaque account id must reject: {literal:?}"
            );
        }
    }
    #[test]
    fn account_json_requires_complete_first_release_shape() {
        let _guard = guard_chain_discriminant();
        let account = Account {
            id: AccountId::new(checked_random_keypair().public_key().clone()),
            metadata: Metadata::default(),
            label: None,
            uaid: None,
            opaque_ids: Vec::new(),
        };
        let value = norito::json::to_value(&account).expect("serialize current account");
        let object = value.as_object().expect("account JSON object");
        assert_eq!(object.get("label"), Some(&norito::json::Value::Null));
        assert_eq!(object.get("uaid"), Some(&norito::json::Value::Null));
        for field in ["metadata", "label", "uaid", "opaque_ids"] {
            let mut missing = value.clone();
            missing
                .as_object_mut()
                .expect("account JSON object")
                .remove(field);
            assert!(
                norito::json::from_value::<Account>(missing).is_err(),
                "current account JSON must reject missing `{field}`"
            );
        }
    }
    #[test]
    fn account_details_json_requires_complete_first_release_shape() {
        let details = AccountDetails::default();
        let value = norito::json::to_value(&details).expect("serialize current account details");
        let object = value.as_object().expect("account details JSON object");
        assert_eq!(object.get("label"), Some(&norito::json::Value::Null));
        assert_eq!(object.get("uaid"), Some(&norito::json::Value::Null));
        for field in ["metadata", "label", "uaid", "opaque_ids"] {
            let mut missing = value.clone();
            missing
                .as_object_mut()
                .expect("account details JSON object")
                .remove(field);
            assert!(
                norito::json::from_value::<AccountDetails>(missing).is_err(),
                "current account details JSON must reject missing `{field}`"
            );
        }
    }
    #[test]
    fn account_id_json_uses_canonical_i105_literal() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let json = norito::json::to_json(&id).expect("serialize account id");
        let i105 = id.canonical_i105().expect("i105 encoding");
        let expected = format!("\"{i105}\"");
        assert_eq!(json, expected);
        let decoded: AccountId = norito::json::from_json(&json).expect("deserialize account id");
        assert_eq!(decoded.controller(), id.controller());

        let map = std::collections::BTreeMap::from([(id.clone(), 7_u8)]);
        let expected_map = format!("{{\"{i105}\":7}}");
        assert_eq!(
            norito::json::to_json(&map).expect("serialize account-key map"),
            expected_map
        );
        assert_eq!(
            norito::json::to_json_bounded(&map, expected_map.len())
                .expect("serialize account-key map at exact bound"),
            expected_map
        );
        assert!(matches!(
            norito::json::to_json_bounded(&map, expected_map.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        ));
    }
    #[test]
    fn account_id_json_object_key_roundtrip_and_bounds() {
        use norito::json::{self, BoundedJsonError, JsonObjectKey};
        use std::collections::BTreeMap;

        let _guard = guard_chain_discriminant();
        let single = AccountId::new(
            checked_keypair_from_seed(vec![0x61; 32])
                .public_key()
                .clone(),
        );
        let members = [0x62, 0x63, 0x64]
            .into_iter()
            .map(|seed| {
                MultisigMember::new(
                    checked_keypair_from_seed(vec![seed; 32])
                        .public_key()
                        .clone(),
                    1,
                )
                .expect("multisig member")
            })
            .collect();
        let multisig = AccountId::new_multisig(MultisigPolicy::new(2, members).expect("policy"));
        for id in [single, multisig] {
            let literal = id.canonical_i105().expect("canonical account text");
            let map = BTreeMap::from([(id.clone(), 7_u8)]);
            let expected = format!("{{\"{literal}\":7}}");
            assert_eq!(json::to_json(&map).expect("account-key map"), expected);
            assert_eq!(
                json::to_json_bounded(&map, expected.len()).expect("exact account-key bound"),
                expected
            );
            assert_eq!(
                json::to_json_bounded(&map, expected.len() - 1),
                Err(BoundedJsonError::BodyTooLarge)
            );
            assert_eq!(
                json::from_str::<BTreeMap<AccountId, u8>>(&expected)
                    .expect("account-key roundtrip"),
                map
            );
            let value: json::Value = json::from_str(&expected).expect("object value");
            assert_eq!(
                <BTreeMap<AccountId, u8> as json::JsonDeserialize>::json_from_value(&value)
                    .expect("account-key value roundtrip"),
                map
            );
            let duplicate = format!("{{\"{literal}\":7,\"{literal}\":8}}");
            assert!(json::from_str::<BTreeMap<AccountId, u8>>(&duplicate).is_err());
            assert_eq!(id.visit_json_key_text(|_| Err(17_u8)), Err(17));
            for failure in [
                BoundedJsonError::BodyTooLarge,
                BoundedJsonError::AllocationFailed,
                BoundedJsonError::LengthMismatch,
                BoundedJsonError::Unsupported,
            ] {
                let mut visits = 0;
                let result = id.visit_json_key_text_checked(|_| {
                    visits += 1;
                    Err(failure.clone())
                });
                assert_eq!(result, Err(failure));
                assert_eq!(visits, 1, "stop on the first visitor failure");
            }
        }
    }
    #[test]
    fn account_id_value_and_map_key_json_decoders_are_borrowed_and_measured() {
        use norito::json::JsonDeserialize as _;

        let _guard = guard_chain_discriminant();
        let id = AccountId::new(checked_random_keypair().public_key().clone());
        let literal = id.canonical_i105().expect("i105 encoding");
        let value = norito::json::Value::String(literal.clone());
        let limits = |bytes| {
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (_, usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            AccountId::json_from_value(&value)
        });
        let exact = usage.total_allocated_bytes();
        for decode in [
            AccountId::json_from_value(&value),
            <AccountId as norito::json::JsonObjectKeyOwned>::from_json_key_text(&literal),
        ] {
            assert_eq!(decode.expect("borrowed AccountId JSON decode"), id);
        }
        for decode in [
            norito::core::with_decode_limits_measured(limits(exact), || {
                AccountId::json_from_value(&value)
            }),
            norito::core::with_decode_limits_measured(limits(exact), || {
                <AccountId as norito::json::JsonObjectKeyOwned>::from_json_key_text(&literal)
            }),
        ] {
            assert_eq!(decode.0.expect("exact AccountId budget"), id);
            assert_eq!(decode.1.total_allocated_bytes(), exact);
        }
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact - 1), || {
            <AccountId as norito::json::JsonObjectKeyOwned>::from_json_key_text(&literal)
        });
        assert!(matches!(
            decoded,
            Err(norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert!(usage.total_allocated_bytes() < exact);
    }
    #[test]
    fn account_id_json_roundtrips_large_multisig_as_canonical_i105() {
        let _guard = guard_chain_discriminant();
        let member_count = (u8::MAX as usize) + 1;
        let mut members = Vec::with_capacity(member_count);
        for idx in 0..member_count {
            let mut seed = vec![0xA5_u8; 32];
            seed[..8].copy_from_slice(&(idx as u64).to_le_bytes());
            let keypair = checked_keypair_from_seed(seed);
            let member = MultisigMember::new(keypair.public_key().clone(), 1).expect("member");
            members.push(member);
        }
        let policy = MultisigPolicy::new(1, members).expect("policy");
        let id = AccountId::new_multisig(policy);
        let json = norito::json::to_json(&id).expect("serialize large multisig account id");
        let i105 = id.canonical_i105().expect("i105 encoding");
        assert_eq!(json, format!("\"{i105}\""));
        let decoded: AccountId =
            norito::json::from_json(&json).expect("deserialize large multisig account id");
        assert_eq!(decoded, id);
        let limits = |bytes| {
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (_, usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            norito::json::from_str::<AccountId>(&json)
        });
        let exact = usage.total_allocated_bytes();
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact), || {
            norito::json::from_str::<AccountId>(&json)
        });
        assert_eq!(decoded.expect("exact large-multisig budget"), id);
        assert_eq!(usage.total_allocated_bytes(), exact);
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact - 1), || {
            norito::json::from_str::<AccountId>(&json)
        });
        assert!(matches!(
            decoded,
            Err(norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert!(usage.total_allocated_bytes() < exact);
    }
    #[test]
    fn account_id_json_rejects_legacy_norito_literal() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let payload_hex = hex::encode(id.encode());
        let legacy = format!("\"norito:{payload_hex}\"");
        let err = norito::json::from_json::<AccountId>(&legacy)
            .expect_err("legacy norito account literal must fail");
        let msg = err.to_string();
        assert!(
            msg.to_ascii_lowercase().contains("i105"),
            "unexpected error: {msg}"
        );
    }
    #[test]
    fn new_account_json_roundtrip_defaults() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let new_account = NewAccount::new(id.clone());
        let json = norito::json::to_json(&new_account).expect("serialize new account");
        let decoded: NewAccount = norito::json::from_json(&json).expect("deserialize new account");
        assert_eq!(decoded, new_account);
        assert!(decoded.label.is_none());
        assert!(decoded.uaid.is_none());
        assert_eq!(decoded.metadata, Metadata::default());
        let removed_field = concat!("linked", "_domains");
        assert!(
            !json.contains(removed_field),
            "domainless registration payloads must not serialize the removed domain-link field"
        );
    }
    #[test]
    fn new_domainless_account_json_roundtrip_defaults() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let new_account = NewAccount::new(id.clone());
        let json = norito::json::to_json(&new_account).expect("serialize new account");
        let decoded: NewAccount = norito::json::from_json(&json).expect("deserialize new account");
        assert_eq!(decoded, new_account);
        assert!(decoded.label.is_none());
        assert!(decoded.uaid.is_none());
        assert_eq!(decoded.metadata, Metadata::default());
    }
    #[test]
    fn new_account_json_roundtrip_with_alias_and_uaid() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let mut metadata = Metadata::default();
        metadata.insert("title".parse().expect("key"), "queen");
        let label = rekey::AccountAlias::new(
            "alice".parse::<Name>().expect("label name"),
            Some(rekey::AccountAliasDomain::new(
                "wonderland".parse::<Name>().expect("alias domain"),
            )),
            DataSpaceId::UNIVERSAL,
        );
        let uaid = UniversalAccountId::from_hash(Hash::prehashed([0xAB; 32]));
        let new_account = NewAccount {
            id: id.clone(),
            metadata: metadata.clone(),
            label: Some(label.clone()),
            uaid: Some(uaid),
            opaque_ids: Vec::new(),
        };
        let json = norito::json::to_json(&new_account).expect("serialize new account");
        let decoded: NewAccount = norito::json::from_json(&json).expect("deserialize new account");
        assert_eq!(decoded, new_account);
        assert_eq!(decoded.label, Some(label));
        assert_eq!(decoded.uaid, Some(uaid));
        assert_eq!(decoded.metadata, metadata);
    }
    #[test]
    fn new_account_json_requires_complete_first_release_shape() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let account = NewAccount::new(id);
        let value = norito::json::to_value(&account).expect("serialize current new account");
        let object = value.as_object().expect("new account JSON object");
        assert_eq!(object.get("label"), Some(&norito::json::Value::Null));
        assert_eq!(object.get("uaid"), Some(&norito::json::Value::Null));
        assert_eq!(
            object
                .get("opaque_ids")
                .and_then(norito::json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        for field in ["metadata", "label", "uaid", "opaque_ids"] {
            let mut missing = value.clone();
            missing
                .as_object_mut()
                .expect("new account JSON object")
                .remove(field);
            assert!(
                norito::json::from_value::<NewAccount>(missing).is_err(),
                "current new account JSON must reject missing `{field}`"
            );
        }
    }
    #[test]
    fn new_account_norito_roundtrip_preserves_packed_self_delimiting_fields() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let mut metadata = Metadata::default();
        metadata.insert("title".parse().expect("metadata key"), "queen");
        let label = rekey::AccountAlias::new(
            "alice".parse::<Name>().expect("label"),
            Some(rekey::AccountAliasDomain::new(
                "wonderland".parse::<Name>().expect("alias domain"),
            )),
            DataSpaceId::UNIVERSAL,
        );
        let uaid = UniversalAccountId::from_hash(Hash::prehashed([0xAB; 32]));
        let opaque_id = OpaqueAccountId::from_hash(Hash::prehashed([0xCD; 32]));
        let new_account = NewAccount::new(id)
            .with_metadata(metadata)
            .with_label(Some(label))
            .with_uaid(Some(uaid))
            .with_opaque_ids(vec![opaque_id]);
        let bytes = encode_adaptive(&new_account);
        let decoded: NewAccount = decode_adaptive(&bytes).expect("decode new account");
        assert_eq!(decoded, new_account);
    }
    #[test]
    fn register_account_norito_roundtrip_matches_kagami_genesis_shape() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let register = Register::account(NewAccount::new(id));
        let bytes = encode_adaptive(&register);
        let decoded: Register<Account> = decode_adaptive(&bytes).expect("decode register account");
        assert_eq!(decoded, register);
    }
    #[test]
    fn new_account_json_rejects_unknown_fields() {
        let _guard = guard_chain_discriminant();
        let keypair = checked_random_keypair();
        let id = AccountId::new(keypair.public_key().clone());
        let i105 = id.canonical_i105().expect("i105 encoding");
        let payload = format!("{{\"id\":\"{i105}\",\"metadata\":{{}},\"extra\":true}}");
        let err = norito::json::from_json::<NewAccount>(&payload).expect_err("unknown field");
        match err {
            norito::json::Error::UnknownField { field } => assert_eq!(field, "extra"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn canonical_account_json_preserves_original_refusal_fields_scope_and_retry() {
        use norito::core::{
            DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError,
            classify_decode_attempt,
        };
        use norito::json::{JsonDeserialize as _, JsonObjectKeyOwned as _};

        let _chain = guard_chain_discriminant();
        let expected = AccountId::new(
            checked_keypair_from_seed(vec![0x6c; 32])
                .public_key()
                .clone(),
        );
        let literal = expected.canonical_i105().unwrap();
        let value = norito::json::Value::String(literal.clone());
        let wire = norito::json::to_json(&literal).unwrap();
        let source_pointer = value.as_str().unwrap().as_ptr();
        let limits = |bytes| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let decode = |mode| match mode {
            0 => AccountId::json_from_value(&value),
            1 => AccountId::from_json_key_text(&literal),
            2 => norito::json::from_json::<AccountId>(&wire),
            _ => unreachable!("three actual canonical JSON API owners"),
        };
        let demands = [0, 1, 2].map(|mode| {
            let (decoded, usage) =
                norito::core::with_decode_limits_measured(limits(usize::MAX), || decode(mode));
            assert_eq!(decoded.unwrap(), expected);
            let demand = usage.total_allocated_bytes();
            assert!(demand > 0);
            demand
        });
        let context_limit = demands
            .iter()
            .try_fold(0_usize, |total, demand| total.checked_add(*demand))
            .unwrap()
            .checked_mul(2)
            .unwrap();
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original = DecodeBudgetContext::try_new_owned(limits(context_limit), &pool).unwrap();
        let baseline = pool.reserved_bytes();
        // The original pool owns the decoder counters. These ordinary JSON controls do not
        // claim physical admission of the returned account graph.
        for (mode, demand) in demands.into_iter().enumerate() {
            let decode = || decode(mode);
            let mut observed = None;
            let before = original.consumed_allocated_bytes();
            let refusal = original.with(|| norito::with_decode_limits_scope(limits(demand - 1), || {
                classify_decode_attempt(|| {
                    let error = decode().expect_err("one-byte-short canonical decoder must refuse");
                    let norito::json::Error::ScopedDecodeResource(origin) = &error else {
                        panic!("canonical AccountId JSON must retain the original scoped refusal: {error:?}");
                    };
                    observed = Some(origin.clone());
                    Err::<(), _>(error.into_core_error())
                })
            })).unwrap_err();
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
                panic!("canonical JSON must return its exact original observer");
            };
            assert_eq!(returned, observed.unwrap());
            drop(returned);
            assert_eq!(pool.reserved_bytes(), baseline);
            let after_refusal = original.consumed_allocated_bytes();
            assert!(after_refusal >= before);
            // The original outer context records the attempted charge before the
            // narrower inner ceiling refuses it. Its counters are cumulative and
            // must not be refunded or replaced by the failed inner operation.
            assert_eq!(after_refusal - before, u64::try_from(demand).unwrap());
            let retry = original
                .with(decode)
                .expect("same input and original context retry");
            assert_eq!(retry, expected);
            assert_eq!(
                original.consumed_allocated_bytes() - after_refusal,
                u64::try_from(demand).unwrap()
            );
            drop(retry);
            assert_eq!(pool.reserved_bytes(), baseline);

            let (error, usage) =
                norito::core::with_decode_limits_measured(limits(demand - 1), decode);
            let error = error
                .expect_err("same input unscoped quota refusal")
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
        let invalid = AccountId::json_from_value(&norito::json::Value::Bool(false)).unwrap_err();
        assert!(matches!(invalid, norito::json::Error::Message(_)));
        assert_eq!(value.as_str().unwrap().as_ptr(), source_pointer);
        assert_eq!(value.as_str(), Some(literal.as_str()));
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn canonical_account_public_parser_preserves_original_address_cause_and_diagnostics() {
        use norito::core::{
            DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError,
            classify_decode_attempt,
        };

        let _chain = guard_chain_discriminant();
        let expected = AccountId::new(
            checked_keypair_from_seed(vec![0x6d; 32])
                .public_key()
                .clone(),
        );
        let literal = expected.canonical_i105().unwrap();
        let limits = |bytes| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (_, usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            AccountId::parse_encoded(&literal)
        });
        let demand = usage.total_allocated_bytes();
        assert!(demand > 0);
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original =
            DecodeBudgetContext::try_new_owned(limits(demand.checked_mul(4).unwrap()), &pool)
                .unwrap();
        let baseline = pool.reserved_bytes();
        for canonicalize in [false, true] {
            let mut observed = None;
            let refusal = original.with(|| norito::with_decode_limits_scope(limits(demand - 1), || classify_decode_attempt(|| {
                let error = if canonicalize {
                    AccountId::canonicalize(&literal).unwrap_err()
                } else {
                    AccountId::parse_encoded(&literal).unwrap_err()
                };
                assert_eq!(error.code_str(), AccountAddressErrorCode::DecodeResourceLimit.as_str());
                assert!(error.is_decode_resource_limit());
                assert!(std::error::Error::source(&error).unwrap().is::<AccountAddressError>());
                assert!(std::error::Error::source(&error).unwrap().source().unwrap().is::<norito::core::ScopedDecodeResourceError>());
                let AccountIdParseError::Address(AccountAddressError::ScopedDecodeResource(origin)) = error else {
                    panic!("public account parser must preserve the original address refusal");
                };
                observed = Some(origin.clone());
                Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
            }))).unwrap_err();
            assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
            let norito::Error::ScopedDecodeResource(origin) = refusal.into_error() else {
                panic!("original scoped public error")
            };
            assert_eq!(origin, observed.unwrap());
            drop(origin);
            assert_eq!(pool.reserved_bytes(), baseline);
            assert_eq!(
                original
                    .with(|| AccountId::parse_encoded(&literal))
                    .unwrap(),
                expected
            );
        }
        let error = norito::with_decode_limits_scope(limits(demand - 1), || {
            AccountId::parse_encoded(&literal)
        })
        .unwrap_err();
        assert!(
            matches!(error, AccountIdParseError::Address(AccountAddressError::DecodeResource(DecodeResourceError::TotalAllocationExceeded {attempted,limit})) if attempted==u64::try_from(demand).unwrap() && limit==u64::try_from(demand-1).unwrap())
        );
        assert!(matches!(
            AccountId::parse_encoded(" alice@root "),
            Err(AccountIdParseError::InvalidFormat)
        ));
        assert_eq!(
            AccountId::parse_encoded(" alice@root ")
                .unwrap_err()
                .to_string(),
            ERR_ACCOUNT_LITERAL_FORMAT
        );
        let checksum = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSｱ";
        let error = AccountId::parse_encoded(checksum).unwrap_err();
        assert!(matches!(
            error,
            AccountIdParseError::Address(AccountAddressError::ChecksumMismatch)
        ));
        assert_eq!(
            error.code_str(),
            AccountAddressErrorCode::ChecksumMismatch.as_str()
        );
        assert!(!error.is_decode_resource_limit());
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
