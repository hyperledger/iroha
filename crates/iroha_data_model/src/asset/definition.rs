//! Asset definitions and builders.
pub use self::model::*;
use super::{alias::AssetDefinitionAlias, id::AssetDefinitionId};

use crate::{
    DeriveFastJson as DeriveFast, DeriveJsonDeserialize as DeriveJsonDe,
    DeriveJsonSerialize as DeriveJsonSer,
};
use crate::{
    HasMetadata, Identifiable, Registered, Registrable, account::prelude::*,
    isi::error::MintabilityError, sorafs_uri::SorafsUri,
};
use core::fmt;
use derive_more::Display;
use getset::{CopyGetters, Getters};
use iroha_crypto::Hash;
use iroha_data_model_derive::{IdEqOrdHash, RegistrableBuilder, model};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::{NumericSpec, Quantity};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
#[cfg(test)]
use norito::json::Value;
/// Maximum accepted asset human-name length.
pub const MAX_ASSET_NAME_LEN: usize = 128;
/// Maximum accepted asset description length.
pub const MAX_ASSET_DESCRIPTION_LEN: usize = 2048;
/// Validate human-facing asset name.
///
/// # Errors
/// Returns [`crate::error::ParseError`] when `name` is blank, too long, or contains
/// reserved alias separators (`#`/`@`).
pub fn validate_asset_name(name: &str) -> Result<(), iroha_model_base::error::ParseError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(iroha_model_base::error::ParseError::new(
            "asset name must not be blank",
        ));
    }
    if trimmed.len() > MAX_ASSET_NAME_LEN {
        return Err(iroha_model_base::error::ParseError::new(
            "asset name exceeds maximum length",
        ));
    }
    if name.contains('#') || name.contains('@') {
        return Err(iroha_model_base::error::ParseError::new(
            "asset name must not contain `#` or `@`",
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(iroha_model_base::error::ParseError::new(
            "asset name must not contain control characters",
        ));
    }
    Ok(())
}
/// Validate optional human-facing description.
///
/// # Errors
/// Returns [`crate::error::ParseError`] when provided description is blank, too long,
/// or contains control characters.
pub fn validate_asset_description(
    description: Option<&str>,
) -> Result<(), iroha_model_base::error::ParseError> {
    let Some(description) = description else {
        return Ok(());
    };
    if description.trim().is_empty() {
        return Err(iroha_model_base::error::ParseError::new(
            "asset description must not be blank when provided",
        ));
    }
    if description.len() > MAX_ASSET_DESCRIPTION_LEN {
        return Err(iroha_model_base::error::ParseError::new(
            "asset description exceeds maximum length",
        ));
    }
    if description.chars().any(char::is_control) {
        return Err(iroha_model_base::error::ParseError::new(
            "asset description must not contain control characters",
        ));
    }
    Ok(())
}
/// Validate optional alias literal for an asset definition against one allowed name stem.
///
/// ASCII case differences are ignored so UX display labels like `CBDC` can still bind aliases
/// such as `cbdc#centralbank`.
///
/// # Errors
/// Returns [`crate::error::ParseError`] when the alias does not match the allowed asset name stem.
pub fn validate_asset_alias(
    alias: Option<&AssetDefinitionAlias>,
    expected_name: &str,
) -> Result<(), iroha_model_base::error::ParseError> {
    validate_asset_alias_against_names(alias, [expected_name])
}
/// Validate optional alias literal for an asset definition against a set of allowed name stems.
///
/// ASCII case differences are ignored for each allowed stem.
///
/// # Errors
/// Returns [`crate::error::ParseError`] when the alias does not match any allowed asset name stem.
pub fn validate_asset_alias_against_names<I, S>(
    alias: Option<&AssetDefinitionAlias>,
    expected_names: I,
) -> Result<(), iroha_model_base::error::ParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let Some(alias) = alias else {
        return Ok(());
    };
    let alias_name = alias.name_segment();
    if expected_names
        .into_iter()
        .any(|expected_name| alias_name.eq_ignore_ascii_case(expected_name.as_ref()))
    {
        return Ok(());
    }
    Err(iroha_model_base::error::ParseError::new(
        "asset alias name segment must match the asset name",
    ))
}
#[model]
mod model {
    use super::*;
    /// Balance partition policy for transparent asset ownership buckets.
    #[derive(
        Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    #[repr(u8)]
    pub enum AssetBalancePolicy {
        /// Keep balances in a global bucket shared across dataspaces.
        #[display("Global")]
        Global,
        /// Partition balances by the transaction dataspace context.
        #[display("DataspaceRestricted")]
        DataspaceRestricted,
    }
    /// Asset definition defines the type of that asset.
    #[derive(
        Debug,
        Display,
        Clone,
        IdEqOrdHash,
        CopyGetters,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        RegistrableBuilder,
    )]
    #[registrable_builder(
        schema_name = "iroha_data_model::asset::definition::model::NewAssetDefinition"
    )]
    #[display("{id} {spec}{mintable}")]
    #[allow(clippy::multiple_inherent_impl)]
    #[derive(DeriveJsonSer, DeriveJsonDe, DeriveFast)]
    #[norito(no_fast_from_json)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::asset::definition::model::AssetDefinition")]
    pub struct AssetDefinition {
        /// An Identification of the [`AssetDefinition`].
        pub id: AssetDefinitionId,
        /// Human-readable asset name shown in UX surfaces.
        #[getset(get = "pub")]
        pub name: String,
        /// Optional human-readable description.
        #[getset(get = "pub")]
        #[registrable_builder(default = None)]
        pub description: Option<String>,
        /// Optional alias literal (`<name>#<domain>.<dataspace>` or `<name>#<dataspace>`).
        #[getset(get = "pub")]
        #[registrable_builder(default = None)]
        pub alias: Option<AssetDefinitionAlias>,
        /// Numeric spec of this asset.
        #[getset(get_copy = "pub")]
        pub spec: NumericSpec,
        /// Is the asset mintable
        #[getset(get_copy = "pub")]
        #[registrable_builder(default = Mintable::default())]
        pub mintable: Mintable,
        /// `SoraFS` URI to the [`AssetDefinition`] logo.
        #[getset(get = "pub")]
        #[registrable_builder(default = None)]
        pub logo: Option<SorafsUri>,
        /// Metadata of this asset definition as a key-value store.
        #[registrable_builder(default = Metadata::default())]
        pub metadata: Metadata,
        /// Balance partition policy for concrete ownership buckets.
        #[getset(get_copy = "pub")]
        pub balance_scope_policy: AssetBalancePolicy,
        /// Immutable owning domain when the definition is domain-owned.
        ///
        /// Global definitions may also be domain-owned. Alias bindings are routing labels and
        /// are deliberately independent from this ownership relationship. Definitions registered
        /// with [`crate::isi::RegisterDataspaceAssetDefinition`] keep this field absent and store
        /// their exact immutable dataspace home in a separate authoritative ledger binding.
        #[getset(get = "pub")]
        pub owning_domain: Option<DomainId>,
        /// The account that owns this asset. Usually the [`Account`] that registered it.
        #[getset(get = "pub")]
        #[registrable_builder(skip, init = authority.clone())]
        pub owned_by: AccountId,
        /// The total quantity of this asset in existence (sum of all asset values).
        #[getset(get = "pub")]
        #[registrable_builder(skip, init = Quantity::zero())]
        pub total_quantity: Quantity,
        /// Runtime confidential-asset policy controlling shielded operations.
        ///
        /// Registration always initializes this field to [`AssetConfidentialPolicy::default`].
        /// It is deliberately absent from [`NewAssetDefinition`]; verifier-backed activation
        /// must use [`crate::isi::zk::RegisterZkAsset`].
        #[getset(get = "pub")]
        #[registrable_builder(skip, init = AssetConfidentialPolicy::default())]
        pub confidential_policy: AssetConfidentialPolicy,
    }
    /// An assets mintability scheme. `Infinitely` means elastic supply. `Once` is what you want to
    /// use. Don't use `Not` explicitly outside of smartcontracts.
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Default,
    )]
    #[repr(u8)]
    pub enum Mintable {
        /// Regular asset with elastic supply. Can be minted and burned.
        #[default]
        #[display("+")]
        Infinitely,
        /// Non-mintable asset (token), with a fixed supply. Can be burned, and minted **once**.
        #[display("=")]
        Once,
        /// Non-mintable asset (token), with a fixed supply. Can be burned, but not minted.
        #[display("-")]
        Not,
        /// Asset may be minted a limited number of additional times.
        #[display("Limited({_0})")]
        Limited(MintabilityTokens),
    }
    /// Remaining mintability budget for limited assets.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        CopyGetters,
        DeriveJsonSer,
        DeriveJsonDe,
        DeriveFast,
    )]
    #[norito(no_fast_from_json)]
    #[repr(transparent)]
    pub struct MintabilityTokens {
        #[getset(get_copy = "pub")]
        value: u32,
    }
    impl MintabilityTokens {
        /// Construct a new token budget if the value is non-zero.
        #[must_use]
        pub const fn new(value: u32) -> Option<Self> {
            if value == 0 {
                None
            } else {
                Some(Self { value })
            }
        }
        /// Attempt to construct a token budget, returning an error when the provided value is zero.
        ///
        /// # Errors
        /// Returns [`MintabilityError::InvalidMintabilityTokens`] when `value` is zero.
        pub fn try_new(value: u32) -> Result<Self, MintabilityError> {
            Self::new(value).ok_or(MintabilityError::InvalidMintabilityTokens(value))
        }
        /// Decrement the budget by one, returning the remaining value or `None` when it reaches zero.
        #[must_use]
        pub const fn decrement(self) -> Option<Self> {
            if self.value <= 1 {
                None
            } else {
                Some(Self {
                    value: self.value - 1,
                })
            }
        }
    }
    impl From<MintabilityTokens> for u32 {
        fn from(tokens: MintabilityTokens) -> Self {
            tokens.value
        }
    }
    impl fmt::Display for MintabilityTokens {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.value)
        }
    }
    impl Mintable {
        /// Create a limited mintability variant from a pre-validated token budget.
        #[must_use]
        pub const fn limited(tokens: MintabilityTokens) -> Self {
            Self::Limited(tokens)
        }
        /// Attempt to create a limited mintability variant from a raw token value.
        ///
        /// # Errors
        /// Returns [`MintabilityError::InvalidMintabilityTokens`] when `tokens` is zero.
        pub fn limited_from_u32(tokens: u32) -> Result<Self, MintabilityError> {
            MintabilityTokens::try_new(tokens).map(Self::Limited)
        }
        /// Remaining limited token budget, if applicable.
        #[must_use]
        pub const fn remaining_tokens(self) -> Option<MintabilityTokens> {
            match self {
                Self::Limited(tokens) => Some(tokens),
                _ => None,
            }
        }
        /// Consume one unit of mintability budget.
        ///
        /// # Errors
        /// Returns [`MintabilityError::MintUnmintable`] when minting is forbidden.
        pub fn consume_one(&mut self) -> Result<bool, MintabilityError> {
            match *self {
                Self::Infinitely => Ok(false),
                Self::Not => Err(MintabilityError::MintUnmintable),
                Self::Once => {
                    *self = Self::Not;
                    Ok(true)
                }
                Self::Limited(tokens) => {
                    if let Some(next) = tokens.decrement() {
                        *self = Self::Limited(next);
                        Ok(false)
                    } else {
                        *self = Self::Not;
                        Ok(true)
                    }
                }
            }
        }
    }
    /// Operating mode for confidential asset flows.
    #[derive(
        Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    #[repr(u8)]
    pub enum ConfidentialPolicyMode {
        /// Asset behaves transparently; shielded instructions are rejected.
        /// This mode is only valid before confidential activation in ABI V1.
        #[display("TransparentOnly")]
        TransparentOnly,
        /// All issuance and movement must occur through confidential instructions.
        #[display("ShieldedOnly")]
        ShieldedOnly,
        /// Asset may move between transparent and confidential representations.
        #[display("Convertible")]
        Convertible,
    }
    /// Pending transition to a new confidential policy mode.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        CopyGetters,
        Getters,
        DeriveJsonSer,
        DeriveJsonDe,
        DeriveFast,
    )]
    #[norito(no_fast_from_json)]
    pub struct ConfidentialPolicyTransition {
        /// Identifier of the new mode to transition into.
        #[getset(get_copy = "pub")]
        pub new_mode: ConfidentialPolicyMode,
        /// Block height at which the transition becomes effective.
        #[getset(get_copy = "pub")]
        pub effective_height: u64,
        /// Policy mode active before this transition was scheduled.
        #[getset(get_copy = "pub")]
        pub previous_mode: ConfidentialPolicyMode,
        /// Transition identifier used to correlate cancellation and audit records.
        #[getset(get = "pub")]
        pub transition_id: Hash,
        /// Optional conversion window length (in blocks) prior to finalizing the transition.
        #[getset(get = "pub")]
        pub conversion_window: Option<u64>,
    }
    /// Configuration governing whether and how an asset uses confidential flows.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        CopyGetters,
        Getters,
        DeriveJsonSer,
        DeriveJsonDe,
        DeriveFast,
    )]
    #[norito(no_fast_from_json)]
    pub struct AssetConfidentialPolicy {
        /// Current mode for shielded versus transparent handling.
        #[getset(get_copy = "pub")]
        pub mode: ConfidentialPolicyMode,
        /// Digest of the confidential feature set this asset expects.
        #[getset(get = "pub")]
        pub vk_set_hash: Option<Hash>,
        /// Poseidon parameter set identifier expected for proofs referencing this asset.
        #[getset(get_copy = "pub")]
        pub poseidon_params_id: Option<u32>,
        /// Pedersen parameter set identifier expected for commitments associated with this asset.
        #[getset(get_copy = "pub")]
        pub pedersen_params_id: Option<u32>,
        /// Pending transition to a new policy mode, if scheduled.
        #[getset(get = "pub")]
        pub pending_transition: Option<ConfidentialPolicyTransition>,
    }
}
impl AssetDefinition {
    /// Construct builder for [`AssetDefinition`] identifiable by [`AssetDefinitionId`].
    ///
    /// The human-facing `name` is explicit and cannot be omitted from construction.
    #[must_use]
    #[inline]
    pub fn new(
        id: AssetDefinitionId,
        name: impl Into<String>,
        spec: NumericSpec,
        balance_scope_policy: AssetBalancePolicy,
        owning_domain: Option<DomainId>,
    ) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, name.into(), spec, balance_scope_policy, owning_domain)
    }
    /// Construct builder for [`AssetDefinition`] identifiable by [`AssetDefinitionId`].
    ///
    /// The human-facing `name` is explicit and cannot be omitted from construction.
    #[must_use]
    #[inline]
    pub fn numeric(
        id: AssetDefinitionId,
        name: impl Into<String>,
        balance_scope_policy: AssetBalancePolicy,
        owning_domain: Option<DomainId>,
    ) -> <Self as Registered>::With {
        <Self as Registered>::With::new(
            id,
            name.into(),
            NumericSpec::default(),
            balance_scope_policy,
            owning_domain,
        )
    }
    /// Mutable access to asset definition metadata for in-place updates.
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }
    /// Consume one unit of the limited mintability budget.
    ///
    /// # Errors
    /// Returns [`MintabilityError::MintUnmintable`] when the definition cannot be minted.
    pub fn consume_mintability(&mut self) -> Result<bool, MintabilityError> {
        self.mintable.consume_one()
    }
    /// Set mintability mode.
    pub fn set_mintable(&mut self, mintable: Mintable) {
        self.mintable = mintable;
    }
    /// Set the owner of this asset definition.
    pub fn set_owned_by(&mut self, owner: AccountId) {
        self.owned_by = owner;
    }
    /// Set the runtime confidential policy configuration.
    ///
    /// Consensus execution uses this after validating the canonical confidential verifier
    /// registration or a valid policy transition. Asset-registration payloads cannot call it.
    pub fn set_confidential_policy(&mut self, policy: AssetConfidentialPolicy) {
        self.confidential_policy = policy;
    }
}
impl NewAssetDefinition {
    /// Set mintability to [`Mintable::Once`]
    #[inline]
    #[must_use]
    pub fn mintable_once(mut self) -> Self {
        self.mintable = Mintable::Once;
        self
    }
    /// Set mintability to [`Mintable::Limited`] with a pre-validated token budget.
    #[inline]
    #[must_use]
    pub fn mintable_limited(mut self, tokens: MintabilityTokens) -> Self {
        self.mintable = Mintable::limited(tokens);
        self
    }
    /// Try to set mintability to [`Mintable::Limited`] using a raw token value.
    ///
    /// Returns an error when the provided value is zero.
    ///
    /// # Errors
    /// Returns [`MintabilityError::InvalidMintabilityTokens`] when `tokens` is zero.
    pub fn try_mintable_limited(mut self, tokens: u32) -> Result<Self, MintabilityError> {
        self.mintable = Mintable::limited_from_u32(tokens)?;
        Ok(self)
    }
}
/// Register-word encoding of asset-definition registration parameters carried
/// by the IVM `REGISTER_ASSET` syscall.
///
/// The Kotodama compiler encodes `NumericSpec::*` and `Mintable::*` source
/// values with these functions and every contract host decodes them with the
/// same functions, so a contract registers exactly the numeric spec and
/// mintability it names.
pub mod ivm_registration {
    use super::{Mintable, NumericSpec};
    use core::fmt;

    /// Largest scale an encoded [`NumericSpec`] may bound.
    pub const MAX_SCALE: u32 = iroha_primitives::numeric::MAX_DECIMAL_SCALE;
    /// Low two bits of a mintability word select the [`Mintable`] variant.
    const MINTABLE_TAG_MASK: u64 = 0b11;
    const MINTABLE_TAG_INFINITELY: u64 = 0;
    const MINTABLE_TAG_ONCE: u64 = 1;
    const MINTABLE_TAG_NOT: u64 = 2;
    const MINTABLE_TAG_LIMITED: u64 = 3;

    /// A `REGISTER_ASSET` argument that does not encode a valid registration parameter.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RegistrationWordError {
        /// The display name is not UTF-8 or fails [`super::validate_asset_name`].
        DisplayName,
        /// The numeric-spec word is neither `0` nor `scale + 1` for a scale up to 28.
        NumericSpec(u64),
        /// The mintability word has an unknown tag, stray bits, or a zero/oversized
        /// limited token budget.
        Mintable(u64),
    }

    impl fmt::Display for RegistrationWordError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::DisplayName => f.write_str("invalid REGISTER_ASSET display name"),
                Self::NumericSpec(word) => {
                    write!(f, "invalid REGISTER_ASSET numeric spec word {word:#x}")
                }
                Self::Mintable(word) => {
                    write!(f, "invalid REGISTER_ASSET mintability word {word:#x}")
                }
            }
        }
    }

    /// The display name, numeric spec and mintability of one `REGISTER_ASSET` call.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Registration {
        /// Validated display name.
        pub name: String,
        /// Numeric spec every quantity of the definition must satisfy.
        pub spec: NumericSpec,
        /// Mintability of the definition.
        pub mintable: Mintable,
    }

    /// Decode the registration arguments every contract host reads for
    /// `REGISTER_ASSET`: the UTF-8 display-name payload of `r11`, the
    /// numeric-spec word in `r12` and the mintability word in `r13`.
    ///
    /// This is the single decoder shared by every host, so a name, spec or
    /// mintability is either registered exactly as written or rejected
    /// identically everywhere.
    ///
    /// # Errors
    /// Returns [`RegistrationWordError::DisplayName`] for a non-UTF-8 or invalid
    /// display name, and the word errors of [`numeric_spec_from_word`] and
    /// [`mintable_from_word`].
    pub fn decode_registration(
        name: &[u8],
        spec_word: u64,
        mintable_word: u64,
    ) -> Result<Registration, RegistrationWordError> {
        let name = core::str::from_utf8(name)
            .ok()
            .filter(|name| super::validate_asset_name(name).is_ok())
            .ok_or(RegistrationWordError::DisplayName)?
            .to_owned();
        Ok(Registration {
            name,
            spec: numeric_spec_from_word(spec_word)?,
            mintable: mintable_from_word(mintable_word)?,
        })
    }

    impl std::error::Error for RegistrationWordError {}

    /// Encode a [`NumericSpec`]: `0` is unconstrained and `scale + 1` bounds the scale.
    #[must_use]
    pub const fn numeric_spec_word(spec: NumericSpec) -> u64 {
        match spec.scale() {
            None => 0,
            Some(scale) => scale as u64 + 1,
        }
    }

    /// Decode a numeric-spec word produced by [`numeric_spec_word`].
    ///
    /// # Errors
    /// Returns [`RegistrationWordError::NumericSpec`] for a scale above [`MAX_SCALE`].
    pub fn numeric_spec_from_word(word: u64) -> Result<NumericSpec, RegistrationWordError> {
        if word == 0 {
            return Ok(NumericSpec::unconstrained());
        }
        u32::try_from(word - 1)
            .ok()
            .and_then(|scale| NumericSpec::try_fractional(scale).ok())
            .ok_or(RegistrationWordError::NumericSpec(word))
    }

    /// Encode a [`Mintable`]: the low two bits select `Infinitely`, `Once`, `Not` or
    /// `Limited`, and the remaining bits carry the limited token budget.
    #[must_use]
    pub fn mintable_word(mintable: Mintable) -> u64 {
        match mintable {
            Mintable::Infinitely => MINTABLE_TAG_INFINITELY,
            Mintable::Once => MINTABLE_TAG_ONCE,
            Mintable::Not => MINTABLE_TAG_NOT,
            Mintable::Limited(tokens) => (u64::from(u32::from(tokens)) << 2) | MINTABLE_TAG_LIMITED,
        }
    }

    /// Decode a mintability word produced by [`mintable_word`].
    ///
    /// # Errors
    /// Returns [`RegistrationWordError::Mintable`] when a non-limited tag carries
    /// payload bits or a limited budget is zero or does not fit `u32`.
    pub fn mintable_from_word(word: u64) -> Result<Mintable, RegistrationWordError> {
        let payload = word >> 2;
        match word & MINTABLE_TAG_MASK {
            MINTABLE_TAG_INFINITELY if payload == 0 => Ok(Mintable::Infinitely),
            MINTABLE_TAG_ONCE if payload == 0 => Ok(Mintable::Once),
            MINTABLE_TAG_NOT if payload == 0 => Ok(Mintable::Not),
            MINTABLE_TAG_LIMITED => u32::try_from(payload)
                .ok()
                .and_then(|tokens| Mintable::limited_from_u32(tokens).ok())
                .ok_or(RegistrationWordError::Mintable(word)),
            _ => Err(RegistrationWordError::Mintable(word)),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn numeric_spec_words_round_trip_and_reject_oversized_scales() {
            for spec in [
                NumericSpec::unconstrained(),
                NumericSpec::integer(),
                NumericSpec::fractional(2),
                NumericSpec::fractional(MAX_SCALE),
            ] {
                assert_eq!(numeric_spec_from_word(numeric_spec_word(spec)), Ok(spec));
            }
            assert_eq!(numeric_spec_word(NumericSpec::unconstrained()), 0);
            assert_eq!(numeric_spec_word(NumericSpec::integer()), 1);
            let oversized = u64::from(MAX_SCALE) + 2;
            assert_eq!(
                numeric_spec_from_word(oversized),
                Err(RegistrationWordError::NumericSpec(oversized))
            );
            assert!(numeric_spec_from_word(u64::MAX).is_err());
        }

        #[test]
        fn mintable_words_round_trip_and_reject_malformed_words() {
            for mintable in [
                Mintable::Infinitely,
                Mintable::Once,
                Mintable::Not,
                Mintable::limited_from_u32(1).expect("one token"),
                Mintable::limited_from_u32(u32::MAX).expect("max tokens"),
            ] {
                assert_eq!(mintable_from_word(mintable_word(mintable)), Ok(mintable));
            }
            assert_eq!(mintable_word(Mintable::Infinitely), 0);
            assert_eq!(mintable_word(Mintable::Once), 1);
            assert_eq!(mintable_word(Mintable::Not), 2);
            for malformed in [
                0b100,
                0b101,
                0b110,
                MINTABLE_TAG_LIMITED,
                ((u64::from(u32::MAX) + 1) << 2) | MINTABLE_TAG_LIMITED,
            ] {
                assert_eq!(
                    mintable_from_word(malformed),
                    Err(RegistrationWordError::Mintable(malformed))
                );
            }
        }

        #[test]
        fn registration_decodes_name_spec_and_mintability_together() {
            let spec = NumericSpec::fractional(2);
            let mintable = Mintable::limited_from_u32(3).expect("token budget");
            assert_eq!(
                decode_registration(b"Rose", numeric_spec_word(spec), mintable_word(mintable)),
                Ok(Registration {
                    name: "Rose".to_owned(),
                    spec,
                    mintable,
                })
            );
            for name in [&b""[..], b"   ", b"ro#se", b"ro@se", b"\xff\xfe"] {
                assert_eq!(
                    decode_registration(name, 0, 0),
                    Err(RegistrationWordError::DisplayName),
                    "{name:?}"
                );
            }
            assert_eq!(
                decode_registration(b"Rose", 30, 0),
                Err(RegistrationWordError::NumericSpec(30))
            );
            assert_eq!(
                decode_registration(b"Rose", 0, 0b100),
                Err(RegistrationWordError::Mintable(0b100))
            );
        }
    }
}
impl Default for AssetConfidentialPolicy {
    fn default() -> Self {
        Self {
            mode: ConfidentialPolicyMode::TransparentOnly,
            vk_set_hash: None,
            poseidon_params_id: None,
            pedersen_params_id: None,
            pending_transition: None,
        }
    }
}
impl AssetConfidentialPolicy {
    fn transition_is_valid_for_current_mode(
        &self,
        transition: ConfidentialPolicyTransition,
    ) -> bool {
        transition.previous_mode == self.mode
            && matches!(
                (self.mode, transition.new_mode),
                (
                    ConfidentialPolicyMode::Convertible,
                    ConfidentialPolicyMode::ShieldedOnly
                ) | (
                    ConfidentialPolicyMode::ShieldedOnly,
                    ConfidentialPolicyMode::Convertible
                )
            )
            && transition.effective_height > 0
            && match transition.new_mode {
                ConfidentialPolicyMode::ShieldedOnly => transition
                    .conversion_window
                    .is_some_and(|window| window > 0 && window <= transition.effective_height),
                ConfidentialPolicyMode::Convertible => transition.conversion_window.is_none(),
                ConfidentialPolicyMode::TransparentOnly => false,
            }
    }
    /// Return whether the persisted pending transition has a valid ABI V1 shape.
    ///
    /// This is a recovery boundary as well as a runtime invariant: authenticated
    /// snapshots must not defer malformed policy state until its advertised height.
    #[must_use]
    pub fn pending_transition_is_valid(&self) -> bool {
        self.pending_transition
            .is_none_or(|transition| self.transition_is_valid_for_current_mode(transition))
    }
    /// Create a transparent-only policy.
    #[must_use]
    pub fn transparent() -> Self {
        Self::default()
    }
    /// Create a shielded-only policy without pending transitions.
    #[must_use]
    pub fn shielded_only() -> Self {
        Self {
            mode: ConfidentialPolicyMode::ShieldedOnly,
            ..Self::default()
        }
    }
    /// Create a convertible policy without pending transitions.
    #[must_use]
    pub fn convertible() -> Self {
        Self {
            mode: ConfidentialPolicyMode::Convertible,
            ..Self::default()
        }
    }
    /// Compute a digest summarizing the confidential feature expectations.
    #[must_use]
    pub fn features_digest(&self) -> Hash {
        let mut buf = Vec::with_capacity(Hash::LENGTH + 8 + 8);
        if let Some(hash) = &self.vk_set_hash {
            buf.extend_from_slice(hash.as_ref());
        } else {
            buf.extend_from_slice(&[0u8; Hash::LENGTH]);
        }
        buf.extend_from_slice(&self.poseidon_params_id.unwrap_or_default().to_le_bytes());
        buf.extend_from_slice(&self.pedersen_params_id.unwrap_or_default().to_le_bytes());
        Hash::new(&buf)
    }
    /// Determine the policy mode that should be in effect at `block_height`.
    ///
    /// Returns the pending transition's mode once the effective height is reached.
    /// A transition outside the ABI V1 confidential state machine is ignored.
    /// In particular, confidential activation is possible only through
    /// verifier registration and can never be reversed to `TransparentOnly`.
    #[must_use]
    pub fn effective_mode(&self, block_height: u64) -> ConfidentialPolicyMode {
        if let Some(transition) = self.pending_transition.as_ref() {
            if !self.transition_is_valid_for_current_mode(*transition) {
                return self.mode;
            }
            if transition.new_mode == ConfidentialPolicyMode::ShieldedOnly
                && let Some(window) = transition.conversion_window()
            {
                let window_open = transition.effective_height().saturating_sub(*window);
                if block_height >= window_open && block_height < transition.effective_height() {
                    return ConfidentialPolicyMode::Convertible;
                }
            }
            if block_height >= transition.effective_height() {
                return transition.new_mode();
            }
        }
        self.mode
    }
    /// Apply the pending transition when it is due, returning the updated policy and
    /// whether a change occurred.
    ///
    /// A transition outside the ABI V1 confidential state machine is discarded
    /// without changing the active mode, even before its advertised height.
    #[must_use]
    pub fn apply_if_due(mut self, block_height: u64) -> (Self, bool) {
        if let Some(transition) = self.pending_transition {
            if !self.transition_is_valid_for_current_mode(transition) {
                self.pending_transition = None;
                return (self, true);
            }
            if transition.new_mode == ConfidentialPolicyMode::ShieldedOnly
                && let Some(window) = transition.conversion_window
            {
                let window_open = transition.effective_height.saturating_sub(window);
                if block_height >= window_open
                    && block_height < transition.effective_height
                    && self.mode != ConfidentialPolicyMode::Convertible
                {
                    self.mode = ConfidentialPolicyMode::Convertible;
                    return (self, true);
                }
            }
            if block_height >= transition.effective_height {
                self.mode = transition.new_mode;
                self.pending_transition = None;
                return (self, true);
            }
        }
        (self, false)
    }
}
impl HasMetadata for AssetDefinition {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

impl norito::json::FastJsonWrite for Mintable {
    fn write_json(&self, out: &mut String) {
        match self {
            Mintable::Infinitely => norito::json::write_json_string("Infinitely", out),
            Mintable::Once => norito::json::write_json_string("Once", out),
            Mintable::Not => norito::json::write_json_string("Not", out),
            Mintable::Limited(tokens) => {
                let label = format!("Limited({})", tokens.value());
                norito::json::write_json_string(&label, out);
            }
        }
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        match self {
            Mintable::Infinitely => norito::json::write_json_string_to("Infinitely", out),
            Mintable::Once => norito::json::write_json_string_to("Once", out),
            Mintable::Not => norito::json::write_json_string_to("Not", out),
            Mintable::Limited(tokens) => {
                norito::json::write_json_string_to(&format!("Limited({})", tokens.value()), out)
            }
        }
    }
}

impl norito::json::FastJsonWrite for ConfidentialPolicyMode {
    fn write_json(&self, out: &mut String) {
        let label = match self {
            ConfidentialPolicyMode::TransparentOnly => "TransparentOnly",
            ConfidentialPolicyMode::ShieldedOnly => "ShieldedOnly",
            ConfidentialPolicyMode::Convertible => "Convertible",
        };
        norito::json::write_json_string(label, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        let label = match self {
            ConfidentialPolicyMode::TransparentOnly => "TransparentOnly",
            ConfidentialPolicyMode::ShieldedOnly => "ShieldedOnly",
            ConfidentialPolicyMode::Convertible => "Convertible",
        };
        norito::json::write_json_string_to(label, out)
    }
}

impl norito::json::FastJsonWrite for AssetBalancePolicy {
    fn write_json(&self, out: &mut String) {
        let label = match self {
            AssetBalancePolicy::Global => "Global",
            AssetBalancePolicy::DataspaceRestricted => "DataspaceRestricted",
        };
        norito::json::write_json_string(label, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        let label = match self {
            AssetBalancePolicy::Global => "Global",
            AssetBalancePolicy::DataspaceRestricted => "DataspaceRestricted",
        };
        norito::json::write_json_string_to(label, out)
    }
}

impl norito::json::JsonDeserialize for ConfidentialPolicyMode {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let label = parser.parse_string()?;
        match label.as_str() {
            "TransparentOnly" => Ok(ConfidentialPolicyMode::TransparentOnly),
            "ShieldedOnly" => Ok(ConfidentialPolicyMode::ShieldedOnly),
            "Convertible" => Ok(ConfidentialPolicyMode::Convertible),
            other => Err(norito::json::Error::InvalidField {
                field: String::from("ConfidentialPolicyMode"),
                message: format!("unknown variant '{other}'"),
            }),
        }
    }
}

impl norito::json::JsonDeserialize for AssetBalancePolicy {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let label = parser.parse_string()?;
        match label.as_str() {
            "Global" => Ok(AssetBalancePolicy::Global),
            "DataspaceRestricted" => Ok(AssetBalancePolicy::DataspaceRestricted),
            other => Err(norito::json::Error::InvalidField {
                field: String::from("AssetBalancePolicy"),
                message: format!("unknown variant '{other}'"),
            }),
        }
    }
}

impl norito::json::JsonDeserialize for Mintable {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let label = parser.parse_string()?;
        parse_mintable_label(label.as_str())
    }
}

fn parse_mintable_label(label: &str) -> Result<Mintable, norito::json::Error> {
    match label {
        "Infinitely" => Ok(Mintable::Infinitely),
        "Once" => Ok(Mintable::Once),
        "Not" => Ok(Mintable::Not),
        other if other.starts_with("Limited(") && other.ends_with(')') => {
            let inner = &other["Limited(".len()..other.len() - 1];
            let count = inner
                .parse::<u32>()
                .map_err(|_| norito::json::Error::InvalidField {
                    field: String::from("Mintable"),
                    message: format!("invalid Limited token count '{inner}'"),
                })?;
            Mintable::limited_from_u32(count).map_err(|err| norito::json::Error::InvalidField {
                field: String::from("Mintable"),
                message: err.to_string(),
            })
        }
        other => Err(norito::json::Error::InvalidField {
            field: String::from("Mintable"),
            message: format!("unknown variant '{other}'"),
        }),
    }
}
impl HasMetadata for NewAssetDefinition {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}
#[cfg(test)]
mod validation_tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::Numeric;
    use norito::codec::DecodeAll as _;
    // Exact pre-direct-dataspace field order, kept separate from the production builder so a
    // future accidental field append or reorder changes this comparison.
    #[derive(Encode)]
    struct OriginalNewAssetDefinitionV1 {
        id: AssetDefinitionId,
        name: String,
        description: Option<String>,
        alias: Option<AssetDefinitionAlias>,
        spec: NumericSpec,
        mintable: Mintable,
        logo: Option<SorafsUri>,
        metadata: Metadata,
        balance_scope_policy: AssetBalancePolicy,
        owning_domain: Option<DomainId>,
    }
    #[derive(Encode)]
    struct ForgedAssetDefinition {
        id: AssetDefinitionId,
        name: String,
        description: Option<String>,
        alias: Option<AssetDefinitionAlias>,
        spec: NumericSpec,
        mintable: Mintable,
        logo: Option<SorafsUri>,
        metadata: Metadata,
        balance_scope_policy: AssetBalancePolicy,
        owning_domain: Option<DomainId>,
        owned_by: AccountId,
        total_quantity: Numeric,
        confidential_policy: AssetConfidentialPolicy,
    }
    #[derive(Encode)]
    struct ForgedNewAssetDefinitionWithPolicy {
        id: AssetDefinitionId,
        name: String,
        description: Option<String>,
        alias: Option<AssetDefinitionAlias>,
        spec: NumericSpec,
        mintable: Mintable,
        logo: Option<SorafsUri>,
        metadata: Metadata,
        balance_scope_policy: AssetBalancePolicy,
        owning_domain: Option<DomainId>,
        confidential_policy: AssetConfidentialPolicy,
    }
    fn owner() -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![0xA5; 32], Algorithm::Ed25519)
            .expect("derive checked asset-definition fixture owner");
        AccountId::new(key_pair.public_key().clone())
    }

    #[test]
    fn registration_builder_schema_identity_matches_capture() {
        // Controlled pre-declaration report: be82d3661d9e2a79fd1a60d6922f1387d3821a0ad5a65d80d294aca1251caedd.
        let nominal = "iroha_data_model::asset::definition::model::NewAssetDefinition";
        let expected: [u8; 16] = hex::decode("d4baef586e5ae708c1a038ef0e73041f")
            .expect("captured schema hash")
            .try_into()
            .expect("16-byte hash");
        assert_eq!(
            <NewAssetDefinition as norito::NoritoSchema>::nominal_name(),
            nominal
        );
        assert_eq!(
            <NewAssetDefinition as norito::NoritoSchema>::frame_name(),
            nominal
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<NewAssetDefinition>(),
            expected
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<NewAssetDefinition>(),
            expected
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<NewAssetDefinition>(),
            expected
        );
    }

    #[test]
    fn confidential_policy_discards_transitions_outside_the_v1_state_machine() {
        for (mode, previous_mode, new_mode) in [
            (
                ConfidentialPolicyMode::Convertible,
                ConfidentialPolicyMode::Convertible,
                ConfidentialPolicyMode::TransparentOnly,
            ),
            (
                ConfidentialPolicyMode::ShieldedOnly,
                ConfidentialPolicyMode::ShieldedOnly,
                ConfidentialPolicyMode::TransparentOnly,
            ),
            (
                ConfidentialPolicyMode::TransparentOnly,
                ConfidentialPolicyMode::TransparentOnly,
                ConfidentialPolicyMode::Convertible,
            ),
            (
                ConfidentialPolicyMode::TransparentOnly,
                ConfidentialPolicyMode::TransparentOnly,
                ConfidentialPolicyMode::ShieldedOnly,
            ),
            (
                ConfidentialPolicyMode::Convertible,
                ConfidentialPolicyMode::ShieldedOnly,
                ConfidentialPolicyMode::ShieldedOnly,
            ),
        ] {
            let transition = ConfidentialPolicyTransition {
                new_mode,
                effective_height: 10,
                previous_mode,
                transition_id: Hash::prehashed([0xA5; 32]),
                conversion_window: None,
            };
            let policy = AssetConfidentialPolicy {
                mode,
                pending_transition: Some(transition),
                ..AssetConfidentialPolicy::default()
            };
            assert_eq!(policy.effective_mode(10), mode);
            let (before_due, changed) = policy.apply_if_due(9);
            assert_eq!(before_due.mode(), mode);
            assert!(before_due.pending_transition().is_none());
            assert!(changed);
            assert_eq!(policy.effective_mode(10), mode);
        }
    }
    #[test]
    fn confidential_policy_validates_persisted_transition_shape() {
        let valid_to_shielded = ConfidentialPolicyTransition {
            new_mode: ConfidentialPolicyMode::ShieldedOnly,
            effective_height: 20,
            previous_mode: ConfidentialPolicyMode::Convertible,
            transition_id: Hash::prehashed([0x31; 32]),
            conversion_window: Some(5),
        };
        let valid_to_convertible = ConfidentialPolicyTransition {
            new_mode: ConfidentialPolicyMode::Convertible,
            effective_height: 20,
            previous_mode: ConfidentialPolicyMode::ShieldedOnly,
            transition_id: Hash::prehashed([0x32; 32]),
            conversion_window: None,
        };
        for (mode, transition) in [
            (ConfidentialPolicyMode::Convertible, valid_to_shielded),
            (ConfidentialPolicyMode::ShieldedOnly, valid_to_convertible),
        ] {
            let policy = AssetConfidentialPolicy {
                mode,
                pending_transition: Some(transition),
                ..AssetConfidentialPolicy::default()
            };
            assert!(policy.pending_transition_is_valid());
        }
        let malformed = [
            ConfidentialPolicyTransition {
                conversion_window: None,
                ..valid_to_shielded
            },
            ConfidentialPolicyTransition {
                conversion_window: Some(21),
                ..valid_to_shielded
            },
            ConfidentialPolicyTransition {
                effective_height: 0,
                ..valid_to_shielded
            },
            ConfidentialPolicyTransition {
                conversion_window: Some(1),
                ..valid_to_convertible
            },
        ];
        for transition in malformed {
            let policy = AssetConfidentialPolicy {
                mode: transition.previous_mode,
                pending_transition: Some(transition),
                ..AssetConfidentialPolicy::default()
            };
            assert!(!policy.pending_transition_is_valid());
        }
    }
    #[test]
    fn constructors_require_explicit_name() {
        let id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            "rose".parse().expect("name"),
        );
        let numeric = AssetDefinition::numeric(
            id.clone(),
            "Rose",
            crate::asset::AssetBalancePolicy::Global,
            None,
        );
        assert_eq!(numeric.name, "Rose");
        let custom = AssetDefinition::new(
            id,
            "Rose fractional",
            NumericSpec::fractional(2),
            crate::asset::AssetBalancePolicy::Global,
            None,
        );
        assert_eq!(custom.name, "Rose fractional");
    }
    #[test]
    fn constructor_requires_explicit_ownership_intent() {
        let domain = DomainId::try_new("wonderland", "universal").expect("domain");
        let id = AssetDefinitionId::derive_from_components(
            domain.clone(),
            "rose".parse().expect("name"),
        );
        let definition =
            AssetDefinition::numeric(id, "Rose", crate::asset::AssetBalancePolicy::Global, None);
        assert_eq!(definition.alias, None);
        assert_eq!(definition.owning_domain, None);
        let explicit = definition.with_owning_domain(Some(domain.clone()));
        let encoded = explicit.encode();
        let decoded = NewAssetDefinition::decode(&mut encoded.as_slice())
            .expect("canonical registration payload");
        assert_eq!(decoded.id, explicit.id);
        assert_eq!(decoded.alias, None);
        assert_eq!(decoded.owning_domain, Some(domain));
    }
    #[test]
    fn existing_global_and_domain_definition_payloads_keep_original_field_order() {
        let domain = DomainId::try_new("wonderland", "universal").expect("domain");
        for (policy, owning_domain) in [
            (AssetBalancePolicy::Global, None),
            (AssetBalancePolicy::Global, Some(domain.clone())),
            (
                AssetBalancePolicy::DataspaceRestricted,
                Some(domain.clone()),
            ),
        ] {
            let id = AssetDefinitionId::derive_from_components(
                domain.clone(),
                "rose".parse().expect("asset name"),
            );
            let object = AssetDefinition::numeric(id, "Rose", policy, owning_domain);
            let original = OriginalNewAssetDefinitionV1 {
                id: object.id.clone(),
                name: object.name.clone(),
                description: object.description.clone(),
                alias: object.alias.clone(),
                spec: object.spec,
                mintable: object.mintable,
                logo: object.logo.clone(),
                metadata: object.metadata.clone(),
                balance_scope_policy: object.balance_scope_policy,
                owning_domain: object.owning_domain.clone(),
            };
            assert_eq!(object.encode(), original.encode());
            let original_payload = original.encode();
            let restored = NewAssetDefinition::decode_all(&mut original_payload.as_slice())
                .expect("decode original field layout");
            assert_eq!(restored.encode(), original_payload);
        }
    }
    #[test]
    fn new_asset_definition_binary_rejects_custom_confidential_policy() {
        let domain = DomainId::try_new("wonderland", "universal").expect("domain");
        let id =
            AssetDefinitionId::derive_from_components(domain, "rose".parse().expect("asset name"));
        let forged = ForgedNewAssetDefinitionWithPolicy {
            id: id.clone(),
            name: "Rose".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: AssetBalancePolicy::Global,
            owning_domain: None,
            confidential_policy: AssetConfidentialPolicy::convertible(),
        };
        let encoded = forged.encode();
        assert!(
            NewAssetDefinition::decode_all(&mut encoded.as_slice()).is_err(),
            "registration wire must not carry caller-selected confidential policy state"
        );
        let canonical = AssetDefinition::numeric(id, "Rose", AssetBalancePolicy::Global, None);
        let encoded = canonical.encode();
        let decoded = NewAssetDefinition::decode_all(&mut encoded.as_slice())
            .expect("canonical transparent registration payload");
        let registered = decoded.build(&owner());
        assert_eq!(
            registered.confidential_policy(),
            &AssetConfidentialPolicy::default()
        );
    }
    #[test]
    fn negative_numeric_payload_cannot_decode_as_asset_definition_total() {
        let id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            "rose".parse().expect("name"),
        );
        let definition =
            AssetDefinition::numeric(id, "Rose", crate::asset::AssetBalancePolicy::Global, None)
                .build(&owner());
        let forged = ForgedAssetDefinition {
            id: definition.id.clone(),
            name: definition.name.clone(),
            description: definition.description.clone(),
            alias: definition.alias.clone(),
            spec: definition.spec,
            mintable: definition.mintable,
            logo: definition.logo.clone(),
            metadata: definition.metadata.clone(),
            balance_scope_policy: definition.balance_scope_policy,
            owning_domain: definition.owning_domain.clone(),
            owned_by: definition.owned_by.clone(),
            total_quantity: Numeric::new(-1_i32, 0),
            confidential_policy: definition.confidential_policy,
        };
        let encoded = forged.encode();
        assert!(
            AssetDefinition::decode(&mut encoded.as_slice()).is_err(),
            "a signed negative payload must not cross the nominal total-quantity boundary"
        );
    }
    #[test]
    fn asset_name_validation_rejects_blank_and_alias_separators() {
        assert!(validate_asset_name("   ").is_err());
        assert!(validate_asset_name("usd#x").is_err());
        assert!(validate_asset_name("usd@x").is_err());
    }
    #[test]
    fn asset_name_validation_accepts_simple_label() {
        validate_asset_name("USD Coin").expect("valid name");
    }
    #[test]
    fn asset_description_validation_rejects_blank_when_present() {
        assert!(validate_asset_description(Some("  ")).is_err());
        validate_asset_description(None).expect("none is valid");
    }
    #[test]
    fn asset_alias_validation_requires_name_segment_match() {
        let alias: AssetDefinitionAlias = "usd#issuer.main".parse().expect("alias");
        validate_asset_alias(Some(&alias), "usd").expect("matching name segment");
        assert!(validate_asset_alias(Some(&alias), "US Dollar").is_err());
    }
    #[test]
    fn asset_alias_validation_accepts_ascii_case_differences() {
        let alias: AssetDefinitionAlias = "cbdc#centralbank".parse().expect("alias");
        validate_asset_alias(Some(&alias), "CBDC").expect("matching name segment");
    }
    #[test]
    fn asset_alias_validation_accepts_any_allowed_stem() {
        let alias: AssetDefinitionAlias = "usd#issuer.main".parse().expect("alias");
        validate_asset_alias_against_names(Some(&alias), ["US Dollar", "usd"])
            .expect("one allowed display-name stem should be accepted");
    }
}
#[cfg(test)]
mod json_tests {
    use super::*;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use norito::json::{Arena, FastFromJson, TapeWalker};
    use std::str::FromStr;
    #[test]
    fn new_asset_definition_json_roundtrip_omits_confidential_policy() {
        let domain: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let id = AssetDefinitionId::derive_from_components(
            domain.clone(),
            Name::from_str("rose").expect("asset name"),
        );
        let mut metadata = Metadata::default();
        metadata.insert("unit".parse().expect("metadata key"), "bloom");
        let new_definition = NewAssetDefinition {
            id,
            name: "Rose".to_owned(),
            description: Some("Flower-backed settlement unit".to_owned()),
            alias: Some("Rose#issuer.main".parse().expect("asset alias")),
            spec: NumericSpec::fractional(4),
            mintable: Mintable::Limited(MintabilityTokens::try_new(5).expect("tokens")),
            logo: Some(
                "sorafs://bafybeigdyrztk/logo/rose.png"
                    .parse()
                    .expect("sorafs uri"),
            ),
            metadata: metadata.clone(),
            balance_scope_policy: AssetBalancePolicy::DataspaceRestricted,
            owning_domain: Some(domain),
        };
        let json =
            norito::json::to_json(&new_definition).expect("serialize asset definition builder");
        assert!(
            !json.contains("confidential_policy"),
            "registration JSON must not expose confidential policy state"
        );
        let decoded: NewAssetDefinition =
            norito::json::from_json(&json).expect("deserialize asset definition builder");
        assert_eq!(decoded.id, new_definition.id);
        assert_eq!(decoded.name, new_definition.name);
        assert_eq!(decoded.description, new_definition.description);
        assert_eq!(decoded.alias, new_definition.alias);
        assert_eq!(decoded.spec.scale(), new_definition.spec.scale());
        assert_eq!(decoded.mintable, new_definition.mintable);
        assert_eq!(decoded.logo, new_definition.logo);
        assert_eq!(decoded.metadata, metadata);
        assert_eq!(
            decoded.balance_scope_policy,
            new_definition.balance_scope_policy
        );
        assert_eq!(decoded.owning_domain, new_definition.owning_domain);
    }
    #[test]
    fn new_asset_definition_json_rejects_custom_confidential_policy() {
        let definition = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").expect("domain id"),
                Name::from_str("rose").expect("asset name"),
            ),
            "Rose",
            AssetBalancePolicy::Global,
            None,
        );
        let value = norito::json::to_value(&definition).expect("serialize registration payload");
        let Value::Object(mut object) = value else {
            panic!("asset-definition registration payload must be an object");
        };
        object.insert(
            "confidential_policy".to_owned(),
            norito::json::to_value(&AssetConfidentialPolicy::convertible())
                .expect("serialize rejected policy"),
        );
        let forged =
            norito::json::to_json(&Value::Object(object)).expect("serialize malformed payload");
        assert!(
            norito::json::from_json::<NewAssetDefinition>(&forged).is_err(),
            "registration JSON must reject caller-selected confidential policy state"
        );
    }
    #[test]
    fn new_asset_definition_fast_from_json_matches_value() {
        let domain: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let id = AssetDefinitionId::derive_from_components(
            domain,
            Name::from_str("rose").expect("asset name"),
        );
        let new_definition = NewAssetDefinition {
            id,
            name: "Rose".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::fractional(2),
            mintable: Mintable::Once,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let json = norito::json::to_json(&new_definition).expect("serialize asset definition");
        assert!(
            json.contains("\"owning_domain\":null"),
            "unowned global definitions must encode explicit null ownership"
        );
        assert!(
            json.contains("\"balance_scope_policy\":\"Global\""),
            "global balance policy must be encoded explicitly"
        );
        let mut walker = TapeWalker::new(&json);
        let mut arena = Arena::new();
        let parsed =
            <NewAssetDefinition as FastFromJson>::parse(&mut walker, &mut arena).expect("parse");
        assert_eq!(parsed, new_definition);
    }
    #[test]
    fn new_asset_definition_json_rejects_missing_ownership_intent() {
        let domain = DomainId::try_new("wonderland", "universal").expect("domain id");
        let definition = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                domain,
                Name::from_str("rose").expect("asset name"),
            ),
            "Rose",
            crate::asset::AssetBalancePolicy::Global,
            None,
        );
        let value = norito::json::to_value(&definition).expect("serialize registration payload");
        let Value::Object(mut object) = value else {
            panic!("asset-definition registration payload must be an object");
        };
        assert!(object.remove("owning_domain").is_some());
        let missing =
            norito::json::to_json(&Value::Object(object)).expect("serialize malformed payload");
        assert!(
            norito::json::from_json::<NewAssetDefinition>(&missing).is_err(),
            "missing ownership intent must not default to an unowned definition"
        );
    }
    #[test]
    fn new_asset_definition_json_rejects_missing_balance_policy_intent() {
        let definition = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").expect("domain id"),
                Name::from_str("rose").expect("asset name"),
            ),
            "Rose",
            AssetBalancePolicy::Global,
            None,
        );
        let value = norito::json::to_value(&definition).expect("serialize registration payload");
        let Value::Object(mut object) = value else {
            panic!("asset-definition registration payload must be an object");
        };
        assert!(object.remove("balance_scope_policy").is_some());
        let missing =
            norito::json::to_json(&Value::Object(object)).expect("serialize malformed payload");
        assert!(
            norito::json::from_json::<NewAssetDefinition>(&missing).is_err(),
            "missing balance policy intent must not default to Global"
        );
    }
}
