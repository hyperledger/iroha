//! Account controller policies (single key and multisignature).
#![allow(clippy::useless_let_if_seq)]
use super::curve::CurveId;
use blake2::{
    Blake2bMac,
    digest::{Mac, consts::U32},
};
use core::fmt;
use iroha_crypto::{Algorithm, PublicKey, zeroize_value_for_confidential_discard};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{alloc::Layout, vec::Vec};
use thiserror::Error;

#[cfg(test)]
mod borrowed_validation_tests;
mod canonical_decode;
/// Controller responsible for authorising account actions.
#[derive(
    Clone,
    Debug,
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
#[norito(tag = "kind", content = "payload", no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::controller::AccountController")]
pub enum AccountController {
    /// Single public key controls the account.
    Single(PublicKey),
    /// Multisignature policy controls the account.
    Multisig(MultisigPolicy),
}
impl AccountController {
    /// Construct a single-signature controller.
    #[must_use]
    pub fn single(signatory: PublicKey) -> Self {
        Self::Single(signatory)
    }
    /// Construct a multisignature controller.
    #[must_use]
    pub fn multisig(policy: MultisigPolicy) -> Self {
        Self::Multisig(policy)
    }
    /// Borrow the single-signature public key when present.
    #[must_use]
    pub fn single_signatory(&self) -> Option<&PublicKey> {
        match self {
            Self::Single(key) => Some(key),
            Self::Multisig(_) => None,
        }
    }
    /// Borrow the single-signature public key, panicking if the controller is not single-key.
    #[must_use]
    pub fn expect_single_signatory(&self) -> &PublicKey {
        self.single_signatory()
            .expect("account controller must be single-key")
    }
    /// Borrow the multisignature policy when present.
    #[must_use]
    pub fn multisig_policy(&self) -> Option<&MultisigPolicy> {
        match self {
            Self::Single(_) => None,
            Self::Multisig(policy) => Some(policy),
        }
    }
    /// Visit the exact nested allocation layouts made by an admitted clone.
    ///
    /// The caller can sum these borrowed layouts before asking its original
    /// allocation owner for capacity; this method itself does not allocate.
    ///
    /// # Errors
    /// Rejects a malformed stored key or a layout that cannot be represented.
    pub fn for_each_admission_clone_layout(
        &self,
        mut visit: impl FnMut(Layout),
    ) -> Result<(), norito::core::Error> {
        match self {
            Self::Single(key) => visit(key_admission_clone_layout(key)?),
            Self::Multisig(policy) => {
                visit(multisig_members_layout(policy.members.len())?);
                for member in &policy.members {
                    visit(key_admission_clone_layout(&member.public_key)?);
                }
            }
        }
        Ok(())
    }
    /// Fallibly clone the controller through its exact compact-key allocations.
    ///
    /// # Errors
    /// Rejects an allocator or active admission limit refusal, or malformed stored material.
    pub fn try_clone_for_admission(&self) -> Result<Self, norito::core::Error> {
        match self {
            Self::Single(key) => key.try_clone_for_admission().map(Self::Single),
            Self::Multisig(policy) => policy.try_clone_for_admission().map(Self::Multisig),
        }
    }
    /// Wipe controller material before discarding a confidential account copy.
    ///
    /// The controller intentionally becomes invalid and must not be used after
    /// this call. Ordinary ledger account identifiers never call this method;
    /// it exists for decrypted restricted payload containers.
    pub fn zeroize_for_confidential_discard(&mut self) {
        match self {
            Self::Single(public_key) => public_key.zeroize_for_confidential_discard(),
            Self::Multisig(policy) => policy.zeroize_for_confidential_discard(),
        }
    }
}
fn key_admission_clone_layout(key: &PublicKey) -> Result<Layout, norito::core::Error> {
    let (_, payload) = key
        .try_to_bytes()
        .map_err(|_| norito::core::Error::Message("invalid stored public key".to_owned()))?;
    let bytes = payload
        .len()
        .checked_add(1)
        .ok_or(norito::core::Error::AllocationFailed { bytes: u64::MAX })?;
    Layout::array::<u8>(bytes)
        .map_err(|_| norito::core::Error::AllocationFailed { bytes: u64::MAX })
}
fn multisig_members_layout(count: usize) -> Result<Layout, norito::core::Error> {
    Layout::array::<MultisigMember>(count)
        .map_err(|_| norito::core::Error::AllocationFailed { bytes: u64::MAX })
}
impl fmt::Display for AccountController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(_) => write!(f, "single"),
            Self::Multisig(policy) => write!(
                f,
                "multisig(threshold={}, members={})",
                policy.threshold(),
                policy.members().len()
            ),
        }
    }
}
/// Multisignature authorisation policy.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::controller::MultisigPolicy")]
#[norito(validate = "canonical_decode::validate_policy")]
pub struct MultisigPolicy {
    version: u8,
    threshold: u16,
    members: Vec<MultisigMember>,
}
impl MultisigPolicy {
    /// Current policy version for newly created policies.
    pub const CURRENT_VERSION: u8 = 1;
    /// Construct a new multisignature policy.
    ///
    /// # Errors
    ///
    /// Returns [`MultisigPolicyError`] if the supplied configuration is invalid.
    pub fn new(threshold: u16, members: Vec<MultisigMember>) -> Result<Self, MultisigPolicyError> {
        let mut members = members;
        for member in &members {
            member
                .public_key()
                .try_to_bytes()
                .map_err(|_| MultisigPolicyError::MalformedPublicKey)?;
        }
        members.sort_unstable_by(|left, right| {
            let (left_algorithm, left_payload) = left
                .public_key()
                .try_to_bytes()
                .expect("validated member key");
            let (right_algorithm, right_payload) = right
                .public_key()
                .try_to_bytes()
                .expect("validated member key");
            left_algorithm
                .as_static_str()
                .cmp(right_algorithm.as_static_str())
                .then_with(|| left_payload.cmp(right_payload))
        });
        Self::from_serialized(Self::CURRENT_VERSION, threshold, members)
    }
    /// Wipe every member key, weight, and policy threshold before discard.
    ///
    /// The policy intentionally becomes invalid and must not be used after
    /// this call.
    pub fn zeroize_for_confidential_discard(&mut self) {
        for member in &mut self.members {
            member.zeroize_for_confidential_discard();
        }
        zeroize_value_for_confidential_discard(&mut self.version);
        zeroize_value_for_confidential_discard(&mut self.threshold);
        self.members.clear();
        zeroize_value_for_confidential_discard(self.members.spare_capacity_mut());
        drop(core::mem::take(&mut self.members));
    }
    /// Construct a policy from canonical serialized components.
    ///
    /// Unlike [`Self::new`], this boundary rejects members outside canonical
    /// complete-key order instead of silently sorting external identities.
    ///
    /// # Errors
    ///
    /// Returns [`MultisigPolicyError`] if the provided version is unsupported or
    /// the contents fail validation.
    pub fn from_serialized(
        version: u8,
        threshold: u16,
        members: Vec<MultisigMember>,
    ) -> Result<Self, MultisigPolicyError> {
        Self::validate_canonical_members(
            version,
            threshold,
            members
                .iter()
                .map(|member| (member.public_key(), member.weight())),
        )?;
        Ok(Self {
            version,
            threshold,
            members,
        })
    }
    /// Validate borrowed serialized members without cloning keys or normalizing their order.
    ///
    /// # Errors
    /// Preserves the serialized constructor's version, count, threshold, key,
    /// weight and complete-key ordering failures before any ownership transfer.
    pub(crate) fn validate_canonical_members<'a>(
        version: u8,
        threshold: u16,
        members: impl ExactSizeIterator<Item = (&'a PublicKey, u16)>,
    ) -> Result<(), MultisigPolicyError> {
        if version != Self::CURRENT_VERSION {
            return Err(MultisigPolicyError::UnsupportedVersion(version));
        }
        if members.len() == 0 {
            return Err(MultisigPolicyError::EmptyMembers);
        }
        if members.len() > usize::from(u16::MAX) {
            return Err(MultisigPolicyError::TooManyMembers(members.len()));
        }
        if threshold == 0 {
            return Err(MultisigPolicyError::ZeroThreshold);
        }
        let mut total_weight = 0u32;
        let mut previous: Option<(&'static str, &'a [u8])> = None;
        for (key, weight) in members {
            if weight == 0 {
                return Err(MultisigPolicyError::MemberWeightZero);
            }
            let (algorithm, payload) = key
                .try_to_bytes()
                .map_err(|_| MultisigPolicyError::MalformedPublicKey)?;
            CurveId::try_from_algorithm(algorithm)
                .map_err(|_| MultisigPolicyError::UnsupportedCurve(algorithm))?;
            let current = (algorithm.as_static_str(), payload);
            if let Some(previous) = previous {
                match previous.cmp(&current) {
                    core::cmp::Ordering::Equal => return Err(MultisigPolicyError::DuplicateMember),
                    core::cmp::Ordering::Greater => {
                        return Err(MultisigPolicyError::NonCanonicalMemberOrder);
                    }
                    core::cmp::Ordering::Less => {}
                }
            }
            previous = Some(current);
            // At most u16::MAX members each contribute at most u16::MAX.
            total_weight += u32::from(weight);
        }
        if u32::from(threshold) > total_weight {
            return Err(MultisigPolicyError::ThresholdExceedsTotal {
                threshold,
                total_weight,
            });
        }
        Ok(())
    }
    /// Policy version.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }
    /// Number of approval weight required.
    #[must_use]
    pub fn threshold(&self) -> u16 {
        self.threshold
    }
    /// Borrow the members participating in the policy.
    #[must_use]
    pub fn members(&self) -> &[MultisigMember] {
        &self.members
    }
    /// Clone the canonical member vector with one exact, fallible allocation.
    ///
    /// Member compact keys are then cloned fallibly into the prepaid backing.
    /// This does not acquire a consensus pool charge; the caller must retain
    /// each matching original charge until the cloned policy is dropped.
    ///
    /// # Errors
    /// Rejects malformed stored policy material or an allocation refusal.
    #[allow(unsafe_code)]
    pub fn try_clone_for_admission(&self) -> Result<Self, norito::core::Error> {
        if self.members.is_empty() {
            return Err(norito::core::Error::Message(
                "invalid empty multisig policy".to_owned(),
            ));
        }
        let layout = multisig_members_layout(self.members.len())?;
        // SAFETY: a valid nonempty policy has a nonzero checked layout. The
        // allocator receives exactly that layout; length zero exposes no
        // uninitialized members. Vec drops every initialized member on error.
        let pointer = unsafe { std::alloc::alloc(layout) };
        if pointer.is_null() {
            return Err(norito::core::Error::AllocationFailed {
                bytes: u64::try_from(layout.size()).unwrap_or(u64::MAX),
            });
        }
        // SAFETY: pointer owns exactly Layout::array::<MultisigMember>(count),
        // and each push initializes one slot without exceeding that capacity.
        let member_pointer = core::ptr::NonNull::new(pointer)
            .expect("the allocation pointer was checked non-null")
            .cast::<MultisigMember>()
            .as_ptr();
        let mut members = unsafe { Vec::from_raw_parts(member_pointer, 0, self.members.len()) };
        for member in &self.members {
            members.push(MultisigMember {
                public_key: member.public_key.try_clone_for_admission()?,
                weight: member.weight,
            });
        }
        Ok(Self {
            version: self.version,
            threshold: self.threshold,
            members,
        })
    }
    /// Compute the aggregate weight across all members.
    #[must_use]
    pub fn total_weight(&self) -> u32 {
        self.members
            .iter()
            .map(|member| u32::from(member.weight()))
            .sum()
    }
    /// Fallibly encode the policy into the CTAP2-style canonical CBOR map used
    /// for multisignature fixtures.
    ///
    /// # Errors
    ///
    /// Returns [`MultisigPolicyError::MalformedPublicKey`] if a member key
    /// cannot expose a well-formed compact payload.
    pub fn try_encode_ctap2(&self) -> Result<Vec<u8>, MultisigPolicyError> {
        let mut buffer = Vec::with_capacity(128);
        cbor_write_map_len(&mut buffer, CTAP2_POLICY_FIELD_COUNT);
        cbor_write_unsigned(&mut buffer, u64::from(CTAP2_POLICY_KEY_VERSION));
        cbor_write_unsigned(&mut buffer, u64::from(self.version()));
        cbor_write_unsigned(&mut buffer, u64::from(CTAP2_POLICY_KEY_THRESHOLD));
        cbor_write_unsigned(&mut buffer, u64::from(self.threshold()));
        cbor_write_unsigned(&mut buffer, u64::from(CTAP2_POLICY_KEY_MEMBERS));
        cbor_write_array_len(&mut buffer, self.members().len());
        for member in self.members() {
            cbor_write_map_len(&mut buffer, CTAP2_MEMBER_FIELD_COUNT);
            cbor_write_unsigned(&mut buffer, u64::from(CTAP2_MEMBER_KEY_CURVE));
            let (algorithm, payload) = member
                .public_key()
                .try_to_bytes()
                .map_err(|_| MultisigPolicyError::MalformedPublicKey)?;
            let curve_id = CurveId::try_from_algorithm(algorithm)
                .expect("multisig members validate curve support at construction");
            cbor_write_unsigned(&mut buffer, u64::from(curve_id.as_u8()));
            cbor_write_unsigned(&mut buffer, u64::from(CTAP2_MEMBER_KEY_WEIGHT));
            cbor_write_unsigned(&mut buffer, u64::from(member.weight()));
            cbor_write_unsigned(&mut buffer, u64::from(CTAP2_MEMBER_KEY_KEY_BYTES));
            cbor_write_bytes(&mut buffer, payload);
        }
        Ok(buffer)
    }
    /// Encode the policy into the CTAP2-style canonical CBOR map used for multisignature fixtures.
    #[must_use]
    pub fn encode_ctap2(&self) -> Vec<u8> {
        self.try_encode_ctap2()
            .expect("multisig policy members validate public-key shape at construction")
    }
    /// Fallibly compute the canonical Blake2b-256 digest (personalised) over
    /// the CTAP2-encoded policy.
    ///
    /// # Errors
    ///
    /// Returns [`MultisigPolicyError::MalformedPublicKey`] if CTAP2 encoding
    /// cannot extract a member's compact public-key payload.
    pub fn try_digest_blake2b256(
        &self,
    ) -> Result<[u8; CTAP2_POLICY_DIGEST_LEN], MultisigPolicyError> {
        let encoded = self.try_encode_ctap2()?;
        let mut hasher =
            Blake2bMac::<U32>::new_with_salt_and_personal(&[], &[], CTAP2_POLICY_PERSONALISATION)
                .expect("personalised Blake2b parameters must be valid");
        Mac::update(&mut hasher, &encoded);
        let mut output = [0u8; CTAP2_POLICY_DIGEST_LEN];
        let tag = hasher.finalize().into_bytes();
        output.copy_from_slice(&tag);
        Ok(output)
    }
    /// Compute the canonical Blake2b-256 digest (personalised) over the CTAP2-encoded policy.
    #[must_use]
    pub fn digest_blake2b256(&self) -> [u8; CTAP2_POLICY_DIGEST_LEN] {
        self.try_digest_blake2b256()
            .expect("multisig policy members validate public-key shape at construction")
    }
}
/// Participant in a multisignature policy.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::controller::MultisigMember")]
#[norito(validate = "canonical_decode::validate_member")]
pub struct MultisigMember {
    public_key: PublicKey,
    weight: u16,
}
impl MultisigMember {
    /// Construct a new multisignature member.
    ///
    /// # Errors
    ///
    /// Rejects zero weight, malformed keys and unsupported signing curves.
    pub fn new(public_key: PublicKey, weight: u16) -> Result<Self, MultisigPolicyError> {
        Self::validate_components(&public_key, weight)?;
        Ok(Self { public_key, weight })
    }
    /// Validate the original borrowed member before transferring its funded key.
    ///
    /// Uses the constructor's validation order without consuming, cloning or
    /// changing the key. Retained decoders can therefore reject and retry while
    /// keeping the same original compact backing and allocation charge.
    ///
    /// # Errors
    /// Rejects zero weight, malformed keys and unsupported signing curves.
    pub(crate) fn validate_components(
        public_key: &PublicKey,
        weight: u16,
    ) -> Result<(), MultisigPolicyError> {
        if weight == 0 {
            return Err(MultisigPolicyError::MemberWeightZero);
        }
        let algorithm = public_key
            .try_algorithm()
            .map_err(|_| MultisigPolicyError::MalformedPublicKey)?;
        CurveId::try_from_algorithm(algorithm)
            .map_err(|_| MultisigPolicyError::UnsupportedCurve(algorithm))?;
        Ok(())
    }
    fn zeroize_for_confidential_discard(&mut self) {
        self.public_key.zeroize_for_confidential_discard();
        zeroize_value_for_confidential_discard(&mut self.weight);
    }
    /// Borrow the member public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    /// Weight contributed by this member.
    #[must_use]
    pub fn weight(&self) -> u16 {
        self.weight
    }
    /// Try to return the signing algorithm used by the member.
    ///
    /// # Errors
    ///
    /// Returns [`MultisigPolicyError::MalformedPublicKey`] if the stored
    /// public key payload is malformed.
    pub fn try_algorithm(&self) -> Result<Algorithm, MultisigPolicyError> {
        self.public_key
            .try_algorithm()
            .map_err(|_| MultisigPolicyError::MalformedPublicKey)
    }
    /// Signing algorithm used by the member.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.try_algorithm()
            .expect("validated multisig member public key must remain well-formed")
    }
}
impl TryFrom<(&PublicKey, u16)> for MultisigMember {
    type Error = MultisigPolicyError;
    fn try_from(value: (&PublicKey, u16)) -> Result<Self, Self::Error> {
        Self::new(value.0.clone(), value.1)
    }
}
impl TryFrom<(PublicKey, u16)> for MultisigMember {
    type Error = MultisigPolicyError;
    fn try_from(value: (PublicKey, u16)) -> Result<Self, Self::Error> {
        Self::new(value.0, value.1)
    }
}
/// Errors raised while constructing multisignature policies.
#[allow(variant_size_differences, clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MultisigPolicyError {
    /// Multisignature policies require at least one member.
    #[error("multisig policy requires at least one member")]
    EmptyMembers,
    /// Member count exceeds the canonical address's u16 capacity.
    #[error("multisig policy has too many members: {0}")]
    TooManyMembers(usize),
    /// Serialized members are not in canonical complete-key order.
    #[error("multisig members are not in canonical key order")]
    NonCanonicalMemberOrder,
    /// Threshold cannot be zero.
    #[error("multisig threshold must be at least 1")]
    ZeroThreshold,
    /// Member weight must be positive.
    #[error("multisig member weight must be at least 1")]
    MemberWeightZero,
    /// Multisig member uses an unsupported signing curve.
    #[error("multisig member uses unsupported curve: {0}")]
    UnsupportedCurve(Algorithm),
    /// Multisig member public key is malformed.
    #[error("multisig member public key is malformed")]
    MalformedPublicKey,
    /// Duplicate member encountered.
    #[error("duplicate multisig member public key")]
    DuplicateMember,
    /// Threshold exceeds the aggregate member weight.
    #[error("multisig threshold {threshold} exceeds total member weight {total_weight}")]
    ThresholdExceedsTotal {
        /// Required approval weight.
        threshold: u16,
        /// Aggregate weight contributed by members.
        total_weight: u32,
    },
    /// Policy version is not supported.
    #[error("unsupported multisig policy version: {0}")]
    UnsupportedVersion(u8),
}
const CTAP2_POLICY_FIELD_COUNT: usize = 3;
const CTAP2_MEMBER_FIELD_COUNT: usize = 3;
const CTAP2_POLICY_KEY_VERSION: u8 = 0x01;
const CTAP2_POLICY_KEY_THRESHOLD: u8 = 0x02;
const CTAP2_POLICY_KEY_MEMBERS: u8 = 0x03;
const CTAP2_MEMBER_KEY_CURVE: u8 = 0x01;
const CTAP2_MEMBER_KEY_WEIGHT: u8 = 0x02;
const CTAP2_MEMBER_KEY_KEY_BYTES: u8 = 0x03;
const CTAP2_POLICY_DIGEST_LEN: usize = 32;
const CTAP2_POLICY_PERSONALISATION: &[u8] = b"iroha-ms-policy";
fn cbor_write_unsigned(buffer: &mut Vec<u8>, value: u64) {
    match value {
        0..=23 => buffer.push(u8::try_from(value).expect("value fits u8")),
        24..=0xFF => {
            buffer.push(0x18);
            buffer.push(u8::try_from(value).expect("value fits u8"));
        }
        0x100..=0xFFFF => {
            buffer.push(0x19);
            let truncated = u16::try_from(value).expect("value fits u16");
            buffer.extend_from_slice(&truncated.to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            buffer.push(0x1A);
            let truncated = u32::try_from(value).expect("value fits u32");
            buffer.extend_from_slice(&truncated.to_be_bytes());
        }
        _ => {
            buffer.push(0x1B);
            buffer.extend_from_slice(&value.to_be_bytes());
        }
    }
}
fn cbor_write_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) {
    cbor_write_len(buffer, 0b010, bytes.len());
    buffer.extend_from_slice(bytes);
}
fn cbor_write_map_len(buffer: &mut Vec<u8>, len: usize) {
    cbor_write_len(buffer, 0b101, len);
}
fn cbor_write_array_len(buffer: &mut Vec<u8>, len: usize) {
    cbor_write_len(buffer, 0b100, len);
}
fn cbor_write_len(buffer: &mut Vec<u8>, major: u8, len: usize) {
    debug_assert!(major <= 0b111, "major type must fit in 3 bits");
    let base = major << 5;
    let value = len as u64;
    match value {
        0..=23 => buffer.push(base | u8::try_from(value).expect("length fits u8")),
        24..=0xFF => {
            buffer.push(base | 24);
            buffer.push(u8::try_from(value).expect("length fits u8"));
        }
        0x100..=0xFFFF => {
            buffer.push(base | 25);
            let truncated = u16::try_from(value).expect("length fits u16");
            buffer.extend_from_slice(&truncated.to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            buffer.push(base | 26);
            let truncated = u32::try_from(value).expect("length fits u32");
            buffer.extend_from_slice(&truncated.to_be_bytes());
        }
        _ => {
            buffer.push(base | 27);
            buffer.extend_from_slice(&value.to_be_bytes());
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("test fixture random key generation should succeed")
    }
    fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm).unwrap_or_else(|err| {
            panic!("{algorithm:?} test fixture key generation should succeed: {err}")
        })
    }
    fn checked_random_public_key() -> PublicKey {
        checked_random_keypair().public_key().clone()
    }
    #[test]
    fn admitted_controller_clone_matches_exact_single_and_multisig_layouts() {
        let first = checked_random_keypair_with_algorithm(Algorithm::Ed25519)
            .public_key()
            .clone();
        let second = checked_random_keypair_with_algorithm(Algorithm::Ed25519)
            .public_key()
            .clone();
        let single = AccountController::single(first.clone());
        let mut layouts = Vec::new();
        single
            .for_each_admission_clone_layout(|layout| layouts.push(layout))
            .unwrap();
        assert_eq!(layouts.len(), 1);
        assert_eq!(layouts[0].size(), 33);
        assert_eq!(single.try_clone_for_admission().unwrap(), single);

        let multisig = AccountController::multisig(
            MultisigPolicy::new(
                2,
                vec![
                    MultisigMember::new(first, 1).unwrap(),
                    MultisigMember::new(second, 1).unwrap(),
                ],
            )
            .unwrap(),
        );
        layouts.clear();
        multisig
            .for_each_admission_clone_layout(|layout| layouts.push(layout))
            .unwrap();
        assert_eq!(layouts.len(), 3);
        assert_eq!(
            layouts[0],
            std::alloc::Layout::array::<MultisigMember>(2).unwrap()
        );
        assert_eq!(layouts[1].size(), 33);
        assert_eq!(layouts[2].size(), 33);
        assert_eq!(multisig.try_clone_for_admission().unwrap(), multisig);
    }
    #[test]
    fn multisig_members_require_positive_weight() {
        let key = checked_random_public_key();
        assert_eq!(
            MultisigMember::new(key, 0).unwrap_err(),
            MultisigPolicyError::MemberWeightZero
        );
    }
    #[test]
    fn multisig_members_accept_supported_curve() {
        let (public_key, _) =
            checked_random_keypair_with_algorithm(Algorithm::Secp256k1).into_parts();
        let member = MultisigMember::new(public_key.clone(), 1).expect("member must be valid");
        assert_eq!(member.public_key(), &public_key);
        assert_eq!(
            member
                .try_algorithm()
                .expect("member public key must be valid"),
            Algorithm::Secp256k1
        );
        assert_eq!(member.algorithm(), Algorithm::Secp256k1);
    }
    #[test]
    fn multisig_policy_enforces_threshold() {
        let member_keys: Vec<MultisigMember> = (0..3)
            .map(|_| MultisigMember::new(checked_random_public_key(), 1).expect("member"))
            .collect();
        let err = MultisigPolicy::new(4, member_keys.clone()).unwrap_err();
        assert_eq!(
            err,
            MultisigPolicyError::ThresholdExceedsTotal {
                threshold: 4,
                total_weight: 3
            }
        );
        let policy = MultisigPolicy::new(2, member_keys).expect("policy");
        assert_eq!(policy.threshold(), 2);
        assert_eq!(policy.total_weight(), 3);
        assert_eq!(policy.version(), MultisigPolicy::CURRENT_VERSION);
    }
    #[test]
    fn multisig_member_confidential_discard_is_idempotent() {
        let mut member = MultisigMember::new(checked_random_public_key(), 7).expect("member");

        for _ in 0..2 {
            member.zeroize_for_confidential_discard();
            assert_eq!(member.weight, 0);
            assert!(member.public_key.try_to_bytes().is_err());
        }
    }
    #[test]
    fn multisig_policy_confidential_discard_wipes_members_and_allocation_idempotently() {
        let members = vec![
            MultisigMember::new(checked_random_public_key(), 2).expect("member"),
            MultisigMember::new(checked_random_public_key(), 3).expect("member"),
        ];
        let mut policy = MultisigPolicy::new(4, members).expect("policy");
        assert!(policy.members.capacity() >= 2);

        for _ in 0..2 {
            policy.zeroize_for_confidential_discard();
            assert_eq!(policy.version, 0);
            assert_eq!(policy.threshold, 0);
            assert!(policy.members.is_empty());
            assert_eq!(policy.members.capacity(), 0);
        }
    }
    #[test]
    fn multisig_policy_rejects_duplicates() {
        let key = checked_random_public_key();
        let members = vec![
            MultisigMember::new(key.clone(), 1).expect("member"),
            MultisigMember::new(key, 1).expect("member"),
        ];
        assert_eq!(
            MultisigPolicy::new(1, members).unwrap_err(),
            MultisigPolicyError::DuplicateMember
        );
    }
    #[test]
    fn multisig_policy_serialized_version_check() {
        let member = MultisigMember::new(checked_random_public_key(), 1).expect("member");
        assert_eq!(
            MultisigPolicy::from_serialized(2, 1, vec![member.clone()]).unwrap_err(),
            MultisigPolicyError::UnsupportedVersion(2)
        );
        let ok = MultisigPolicy::from_serialized(1, 1, vec![member]).expect("policy");
        assert_eq!(ok.version(), 1);
    }
    #[test]
    fn multisig_policy_ctap2_encoding_and_digest_are_stable() {
        let members: Vec<MultisigMember> = (0..3)
            .map(|seed| {
                let seed_byte = u8::try_from(seed).expect("seed fits u8");
                let bytes = vec![seed_byte.saturating_add(1); 32];
                let (public_key, _) = KeyPair::try_from_seed(bytes, Algorithm::Ed25519)
                    .expect("derive checked multisig fixture keypair")
                    .into_parts();
                MultisigMember::new(public_key, seed + 1).expect("member")
            })
            .collect();
        let policy = MultisigPolicy::new(3, members).expect("policy");
        let encoded = policy.try_encode_ctap2().expect("fallible CTAP2 encoding");
        assert_eq!(encoded, policy.encode_ctap2());
        assert!(
            !encoded.is_empty(),
            "CTAP2 encoding must produce a non-empty payload"
        );
        assert_eq!(
            encoded[0], 0xA3,
            "CTAP2 encoding should begin with a 3-field map header"
        );
        let digest = policy
            .try_digest_blake2b256()
            .expect("fallible CTAP2 digest");
        assert_ne!(
            digest, [0u8; CTAP2_POLICY_DIGEST_LEN],
            "digest must not be zeroed"
        );
        assert_eq!(
            digest,
            policy.digest_blake2b256(),
            "digest computation must be deterministic"
        );
    }
}
