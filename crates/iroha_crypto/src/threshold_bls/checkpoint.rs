//! Authenticated local checkpoint custody for the original DKG secret owners.
//!
//! The private fixed record is canonical Norito inside the existing nonce/AEAD/tag
//! envelope. Only encrypted bytes and opaque checked secret owners leave this module.
//! The caller must authenticate the complete binding from protocol/native state and
//! enforce its durable phase head; an AEAD cannot detect rollback by the disk owner.

use super::*;
use crate::{
    KeyPair, PrivateKey, PrivateKeyInner, hybrid::HybridKeyPair, secrecy::ExposeSecret as _,
};
use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBuffer, PrepaidBufferError};
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeRecordFields, Encoder,
    FieldDestination, PreparedDecodeError, PreparedDecodeScopeError, PreparedDecodeWorkspace,
    PreparedRecordDestination, SerializePayload,
};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};
use std::{alloc::Layout, convert::Infallible, io::Write};

const DOMAIN: &[u8] = b"iroha.dkg.local-secret-checkpoint.v1\0";
const COEFFICIENT_BYTES: usize = MAX_DEALER_COEFFICIENTS_V1 * 96;
const CONTRIBUTION_BYTES: usize = THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize * 96;

/// Exact protocol/native context authenticated as checkpoint associated data.
///
/// This is a context value, not evidence that its fields were verified. The Core
/// and daemon must derive it from the sole finalized native-source verifier, the
/// frozen session and the original durable attempt claim before any restoration.
///
/// The source discriminant separates signed H1 authorization from an executed
/// native tip. A signed H1 body authenticates no result. Only the checked Core
/// attempt owner can authorize a source or derive a frozen protocol cutoff;
/// this crypto value authenticates context and cannot grant protocol authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha_crypto::threshold_bls::checkpoint::DkgCheckpointBindingV1")]
#[norito(decode_fields)]
pub struct DkgCheckpointBindingV1 {
    /// Frozen network identity.
    pub network_id: [u8; 32],
    /// Unique certified transition/attempt identity.
    pub attempt_id: [u8; 32],
    /// Authority generation authenticated by that transition.
    pub authority_generation: u64,
    /// Original DKG session identity.
    pub session_id: [u8; 32],
    /// Exact ordered frozen committee digest.
    pub roster_hash: [u8; 32],
    /// Exact one-based seat index.
    pub seat_index: u16,
    /// Canonical lifecycle public-key digest for this seat.
    pub lifecycle_key_hash: [u8; 32],
    /// Canonical original software custody-provider handle digest.
    pub provider_handle_hash: [u8; 32],
    /// Original software custody-provider revision.
    pub provider_revision: u64,
    /// Frozen session start height.
    pub start_height: u64,
    /// Frozen commitments cutoff.
    pub commitments_end_height: u64,
    /// Frozen deliveries cutoff.
    pub deliveries_end_height: u64,
    /// Frozen acceptances cutoff.
    pub acceptances_end_height: u64,
    /// Exact source kind and context; this DTO does not authenticate finality.
    pub source: DkgCheckpointSourceV1,
    /// Original authenticated attempt cutoff; restoration cannot extend it.
    pub cutoff_height: u64,
    /// Complete phase: 1 generated, 2 delivered, 3 accepted.
    pub phase: u16,
    /// Hash of the immutable original signed public output for this phase.
    pub public_output_hash: [u8; 32],
    /// Exact authenticated input hash, absent only for initial generation.
    pub phase_input_hash: [u8; 32],
    /// Exact immutable write-ahead producer intent, authenticated inside the AEAD.
    pub producer_intent_hash: [u8; 32],
    /// Original prior durable checkpoint hash, absent only for generation.
    pub previous_checkpoint_hash: [u8; 32],
}

/// Canonical context for the original source, without any implicit H1 result.
///
/// A caller may construct this value, but only Core's checked protocol owner
/// grants authority after verifying the original signed body or native journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoSchema)]
#[norito_schema(name = "iroha_crypto::threshold_bls::checkpoint::DkgCheckpointSourceV1")]
#[expect(
    variant_size_differences,
    reason = "bounded inline source context preserves distinct signed-body/native authentication without a heap owner or invented genesis result"
)]
pub enum DkgCheckpointSourceV1 {
    /// Signed height-one body authorizing initial key provisioning only.
    SignedGenesisAuthorization {
        /// Hash of that exact signed genesis header, equal to the network pin.
        genesis_hash: [u8; 32],
    },
    /// Genuine executed source authenticated by its original native finality prefix.
    ExecutedNativeTip {
        /// Ordinary height; a native H1 result needs a genuine H2 parent commitment.
        height: u64,
        /// Hash of the exact committed Iroha block header.
        block_hash: [u8; 32],
        /// Certified native core-header hash.
        core_hash: [u8; 32],
        /// Certified original execution result R.
        result_hash: [u8; 32],
    },
}
// The same canonical variant walk serves ordinary and prepaid destinations.
// Variant tags and field framing remain the existing V1 enum layout. A caller's
// destination changes custody only; the complete enclosing frame still needs
// its original exact canonical comparison and protocol/native authorization.
impl<D> DecodeRecordFields<D> for DkgCheckpointSourceV1
where
    D: FieldDestination
        + DecodeField<0, [u8; 32], Value = [u8; 32]>
        + DecodeField<1, u64, Value = u64>
        + DecodeField<2, [u8; 32], Value = [u8; 32]>
        + DecodeField<3, [u8; 32], Value = [u8; 32]>
        + DecodeField<4, [u8; 32], Value = [u8; 32]>,
{
    type Values = Self;
    fn decode_fields(
        bytes: &[u8],
        destination: &mut D,
    ) -> Result<(Self, usize), DecodeIntoError<D::Error>> {
        let _context = norito::core::PayloadCtxGuard::enter(bytes);
        let mut tag = [0; 4];
        tag.copy_from_slice(norito::core::payload_range_from_ptr(bytes.as_ptr(), 4)?);
        let mut offset = 4;
        let value = match u32::from_le_bytes(tag) {
            0 => Self::SignedGenesisAuthorization {
                genesis_hash: <D as DecodeField<0, [u8; 32]>>::decode_field(
                    destination,
                    norito::core::framed_byte_array_field::<32>(bytes, &mut offset)?,
                )?,
            },
            1 => Self::ExecutedNativeTip {
                height: <D as DecodeField<1, u64>>::decode_field(
                    destination,
                    norito::core::framed_field(bytes, &mut offset)?,
                )?,
                block_hash: <D as DecodeField<2, [u8; 32]>>::decode_field(
                    destination,
                    norito::core::framed_byte_array_field::<32>(bytes, &mut offset)?,
                )?,
                core_hash: <D as DecodeField<3, [u8; 32]>>::decode_field(
                    destination,
                    norito::core::framed_byte_array_field::<32>(bytes, &mut offset)?,
                )?,
                result_hash: <D as DecodeField<4, [u8; 32]>>::decode_field(
                    destination,
                    norito::core::framed_byte_array_field::<32>(bytes, &mut offset)?,
                )?,
            },
            _ => return Err(norito::Error::Message("invalid enum discriminant".into()).into()),
        };
        norito::core::finish_context_fields(bytes.as_ptr(), offset)?;
        Ok((value, offset))
    }
}
impl<'de> norito::core::DeserializePayload<'de> for DkgCheckpointSourceV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).unwrap_or_else(|error| {
            panic!("norito: fallible deserialize failed for DkgCheckpointSourceV1: {error:?}")
        })
    }
    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        norito::core::with_context_fields(std::ptr::from_ref(archived).cast::<u8>(), |bytes| {
            let (value, _) = Self::decode_fields(bytes, &mut norito::core::OwnedFields)
                .map_err(DecodeIntoError::into_codec)?;
            Ok(value)
        })?
    }
}
impl DkgCheckpointSourceV1 {
    /// Height of this context, without implying finality authority.
    #[must_use]
    pub const fn height(&self) -> u64 {
        match self {
            Self::SignedGenesisAuthorization { .. } => 1,
            Self::ExecutedNativeTip { height, .. } => *height,
        }
    }
    fn valid_for(&self, binding: &DkgCheckpointBindingV1) -> bool {
        match self {
            Self::SignedGenesisAuthorization { genesis_hash } => {
                binding.phase == 1
                    && binding.authority_generation == 0
                    && binding.start_height == 1
                    && *genesis_hash == binding.network_id
                    && !is_zero(genesis_hash)
            }
            Self::ExecutedNativeTip {
                height,
                block_hash,
                core_hash,
                result_hash,
            } => {
                *height >= 2 && !is_zero(block_hash) && !is_zero(core_hash) && !is_zero(result_hash)
            }
        }
    }
}

impl DkgCheckpointBindingV1 {
    /// Canonical digest of the actual lifecycle public owner, without allocation.
    ///
    /// # Errors
    /// Returns the original canonical encoder cause.
    pub fn lifecycle_key_digest(key: &crate::PublicKey) -> Result<[u8; 32], norito::Error> {
        let mut writer = HashWriter(Sha256::new());
        writer
            .0
            .update(b"iroha.dkg.local-secret-checkpoint.lifecycle.v1\0");
        norito::core::write_canonical_to_writer(key, &mut writer)?;
        Ok(writer.0.finalize().into())
    }
}

/// Exact local storage, canonical parsing or authentication refusal.
#[derive(Debug, thiserror::Error)]
pub enum DkgCheckpointErrorV1 {
    /// Original physical admission failure.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Original prepaid backing construction failure.
    #[error(transparent)]
    Buffer(#[from] PrepaidBufferError),
    /// Original counter-control construction failure.
    #[error(transparent)]
    Scope(#[from] PreparedDecodeScopeError),
    /// Canonical private record encoding failed.
    #[error(transparent)]
    Encoding(#[from] norito::Error),
    /// The sole canonical prepared field walk refused.
    #[error(transparent)]
    Decode(#[from] PreparedDecodeError<Infallible>),
    /// The original threshold equation or binding failed.
    #[error(transparent)]
    Threshold(#[from] ThresholdBlsError),
    /// Checked hybrid-secret reconstruction failed.
    #[error(transparent)]
    Hybrid(#[from] crate::hybrid::HybridError),
    /// Original entropy or authenticated encryption failed.
    #[error(transparent)]
    Encryption(#[from] crate::encryption::Error),
    /// The complete context, phase geometry, source or checked public output differs.
    #[error("local DKG checkpoint context or original output mismatch")]
    Binding,
    /// Secret production/sealing already started or output extraction completed.
    #[error("local DKG checkpoint producer is terminal")]
    Terminal,
}

// This is the sole private canonical DTO; it is never a public secret export.
// Fixed raw fields avoid all nested Vec or alignment-copy decoding. Unused slots
// are canonical zeros and remain inside the zeroizing physical owner.
#[derive(NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha_crypto::threshold_bls::checkpoint::DkgPrivateCheckpointRecordV1")]
#[norito(decode_fields)]
struct PrivateRecord {
    version: u16,
    purpose: u8,
    parameters_digest: [u8; 32],
    seat_index: u16,
    coefficient_count: u16,
    contribution_count: u16,
    x25519_secret: [u8; 32],
    mlkem768_secret: [u8; 2400],
    coefficients: [u8; COEFFICIENT_BYTES],
    contributions: [u8; CONTRIBUTION_BYTES],
}
impl PrivateRecord {
    fn empty() -> Self {
        Self {
            version: 0,
            purpose: 0,
            parameters_digest: [0; 32],
            seat_index: 0,
            coefficient_count: 0,
            contribution_count: 0,
            x25519_secret: [0; 32],
            mlkem768_secret: [0; 2400],
            coefficients: [0; COEFFICIENT_BYTES],
            contributions: [0; CONTRIBUTION_BYTES],
        }
    }
    fn erase(&mut self) {
        self.version = 0;
        self.purpose = 0;
        self.parameters_digest.zeroize();
        self.seat_index = 0;
        self.coefficient_count = 0;
        self.contribution_count = 0;
        self.x25519_secret.zeroize();
        self.mlkem768_secret.zeroize();
        self.coefficients.zeroize();
        self.contributions.zeroize();
    }
}
impl Drop for PrivateRecord {
    fn drop(&mut self) {
        self.erase();
    }
}
struct PrivateDestination {
    record: ChargedBuffer<PrivateRecord>,
}
impl FieldDestination for PrivateDestination {
    type Error = Infallible;
}
macro_rules! scalar_field {
    ($index:literal, $ty:ty, $field:ident) => {
        impl DecodeField<$index, $ty> for PrivateDestination {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Infallible>> {
                self.record.as_mut_slice()[0].$field = field.with_payload(|bytes| {
                    let (value, used) = <$ty as DecodeFromSlice>::decode_from_slice(bytes)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    Ok(value)
                })?;
                Ok(())
            }
        }
    };
}
macro_rules! fixed_field {
    ($index:literal, $len:expr, $field:ident) => {
        impl DecodeField<$index, [u8; $len]> for PrivateDestination {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, [u8; $len]>,
            ) -> Result<(), DecodeIntoError<Infallible>> {
                field.with_payload(|bytes| {
                    if bytes.len() != $len {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    self.record.as_mut_slice()[0].$field.copy_from_slice(bytes);
                    Ok(())
                })
            }
        }
    };
}
scalar_field!(0, u16, version);
scalar_field!(1, u8, purpose);
fixed_field!(2, 32, parameters_digest);
scalar_field!(3, u16, seat_index);
scalar_field!(4, u16, coefficient_count);
scalar_field!(5, u16, contribution_count);
fixed_field!(6, 32, x25519_secret);
fixed_field!(7, 2400, mlkem768_secret);
fixed_field!(8, COEFFICIENT_BYTES, coefficients);
fixed_field!(9, CONTRIBUTION_BYTES, contributions);
impl SerializePayload for PrivateDestination {
    fn serialize(&self, encoder: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.record.as_slice()[0].serialize(encoder)
    }
}
impl PreparedRecordDestination<PrivateRecord> for PrivateDestination {
    fn reset(&mut self) {
        self.record.as_mut_slice()[0].erase();
    }
}
struct SecretBytes(ChargedBuffer<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}
struct CountWriter(usize);
impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Opaque recovered secret owners; the original accepted-share backing stays charged.
/// No plaintext record, raw secret serialization or new proof is exposed.
pub struct RestoredDkgSecretsV1<P: ThresholdBlsPurpose> {
    recipient: HybridKeyPair,
    dealer: Option<DasRenDealerSecret<P>>,
    contributions: ChargedBuffer<DasRenPrivateShare<P>>,
}
impl<P: ThresholdBlsPurpose> RestoredDkgSecretsV1<P> {
    /// Move checked original crypto owners into the enclosing private seat owner.
    #[must_use]
    pub fn into_owners(
        self,
    ) -> (
        HybridKeyPair,
        Option<DasRenDealerSecret<P>>,
        ChargedBuffer<DasRenPrivateShare<P>>,
    ) {
        (self.recipient, self.dealer, self.contributions)
    }
}

/// All actual checkpoint plaintext, ciphertext, restored-share and decode-control
/// allocations admitted together before the caller creates or signs any secret.
///
/// A successful seal is immutable; retry borrows its original encrypted bytes.
/// Restore is bound to the first offered ciphertext and full context even on a
/// decoder refusal. There is no alternate decoder, plaintext export or reroll.
pub struct PreparedDkgSecretsCheckpointV1<P: ThresholdBlsPurpose> {
    source: SecretBytes,
    work: SecretBytes,
    destination: PrivateDestination,
    shares: Option<ChargedBuffer<DasRenPrivateShare<P>>>,
    workspace: PreparedDecodeWorkspace,
    restored_recipient: Option<HybridKeyPair>,
    restored_dealer: Option<DasRenDealerSecret<P>>,
    parameters: AdaptiveThresholdBlsParameters<P>,
    seat_index: u16,
    binding: Option<[u8; 32]>,
    source_hash: Option<[u8; 32]>,
    sealed: bool,
    restored_phase: u16,
    terminal: bool,
}
impl<P: ThresholdBlsPurpose> PreparedDkgSecretsCheckpointV1<P> {
    /// Physically prepare every fixed destination before RNG, signing or attempt claim.
    ///
    /// # Errors
    /// Preserves geometry, aggregate pool refusal and exact allocator/control errors.
    pub fn new(
        parameters: &AdaptiveThresholdBlsParameters<P>,
        seat_index: u16,
        budget: &AllocationBudget,
    ) -> Result<Self, DkgCheckpointErrorV1> {
        validate_participant_index(parameters.session(), seat_index)?;
        let envelope_len = Self::encrypted_record_bound()?;
        let shares_len = usize::from(parameters.session().committee_size());
        let controls = PreparedDecodeWorkspace::allocation_layouts();
        let mut reservation = budget.try_reserve_layouts([
            Layout::array::<u8>(envelope_len).map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<u8>(envelope_len).map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<PrivateRecord>(1).map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<DasRenPrivateShare<P>>(shares_len)
                .map_err(|_| AllocationRefusal::DemandOverflow)?,
            controls[0],
            controls[1],
        ])?;
        let mut source = ChargedBuffer::from_reservation(envelope_len, &mut reservation)?;
        let mut work = ChargedBuffer::from_reservation(envelope_len, &mut reservation)?;
        for _ in 0..envelope_len {
            source.push_reserved(0);
            work.push_reserved(0);
        }
        let mut record = ChargedBuffer::from_reservation(1, &mut reservation)?;
        record.push_reserved(PrivateRecord::empty());
        let shares = ChargedBuffer::from_reservation(shares_len, &mut reservation)?;
        let workspace = PreparedDecodeWorkspace::from_reservation(budget, &mut reservation)?;
        if reservation.remaining_bytes() != 0 {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        Ok(Self {
            source: SecretBytes(source),
            work: SecretBytes(work),
            destination: PrivateDestination { record },
            shares: Some(shares),
            workspace,
            restored_recipient: None,
            restored_dealer: None,
            parameters: *parameters,
            seat_index,
            binding: None,
            source_hash: None,
            sealed: false,
            restored_phase: 0,
            terminal: false,
        })
    }
    /// Exact canonical encrypted-source bound without preparing any private graph.
    ///
    /// The same fixed record walk is used by the constructor. It performs no
    /// allocation, RNG or secret reconstruction and grants no protocol authority.
    ///
    /// # Errors
    /// Preserves canonical serialization or checked length overflow.
    pub fn encrypted_record_bound() -> Result<usize, DkgCheckpointErrorV1> {
        let mut count = CountWriter(0);
        norito::core::write_canonical_to_writer(&PrivateRecord::empty(), &mut count)?;
        Ok(count
            .0
            .checked_add(28)
            .ok_or(AllocationRefusal::DemandOverflow)?)
    }

    /// Fixed canonical encrypted-source length admitted before claim and production.
    #[must_use]
    pub fn encrypted_record_capacity(&self) -> usize {
        self.source.0.capacity()
    }

    /// Verify every physical allocation still belongs to the original finite pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.source.0.belongs_to(budget)
            && self.work.0.belongs_to(budget)
            && self.destination.record.belongs_to(budget)
            && self.workspace.belongs_to(budget)
            && self
                .shares
                .as_ref()
                .is_some_and(|shares| shares.belongs_to(budget))
    }
    fn context(
        &self,
        binding: &DkgCheckpointBindingV1,
        lifecycle: &KeyPair,
    ) -> Result<[u8; 32], DkgCheckpointErrorV1> {
        let session = self.parameters.session();
        if binding.network_id != *session.network_id()
            || binding.session_id != *session.session_id()
            || binding.roster_hash != *session.roster_hash()
            || binding.seat_index != self.seat_index
            || is_zero(&binding.attempt_id)
            || is_zero(&binding.lifecycle_key_hash)
            || !binding.source.valid_for(binding)
            || binding.provider_revision == 0
            || is_zero(&binding.provider_handle_hash)
            || is_zero(&binding.public_output_hash)
            || is_zero(&binding.producer_intent_hash)
            || binding.start_height >= binding.commitments_end_height
            || binding.commitments_end_height >= binding.deliveries_end_height
            || binding.deliveries_end_height >= binding.acceptances_end_height
            || binding.source.height() < binding.start_height
            || binding.source.height() >= binding.cutoff_height
            || binding.cutoff_height <= binding.acceptances_end_height
            || !(1..=3).contains(&binding.phase)
            || (binding.phase == 1 && binding.source.height() >= binding.commitments_end_height)
            || (binding.phase == 2
                && (binding.source.height() < binding.commitments_end_height
                    || binding.source.height() >= binding.deliveries_end_height))
            || (binding.phase == 3
                && (binding.source.height() < binding.deliveries_end_height
                    || binding.source.height() >= binding.acceptances_end_height))
            || (binding.phase == 1
                && (!is_zero(&binding.phase_input_hash)
                    || !is_zero(&binding.previous_checkpoint_hash)))
            || (binding.phase != 1
                && (is_zero(&binding.phase_input_hash)
                    || is_zero(&binding.previous_checkpoint_hash)))
            || lifecycle.public_key().algorithm() != crate::Algorithm::BlsNormal
        {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        if DkgCheckpointBindingV1::lifecycle_key_digest(lifecycle.public_key())?
            != binding.lifecycle_key_hash
        {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        let mut hash = HashWriter(Sha256::new());
        hash.0.update(DOMAIN);
        hash.0.update([P::ROLE_TAG]);
        norito::core::write_canonical_to_writer(binding, &mut hash)?;
        Ok(hash.0.finalize().into())
    }
    fn cipher(
        lifecycle: &PrivateKey,
        digest: &[u8; 32],
    ) -> Result<SymmetricEncryptor<ChaCha20Poly1305>, DkgCheckpointErrorV1> {
        let PrivateKeyInner::BlsNormal(secret) = lifecycle.0.expose_secret() else {
            return Err(DkgCheckpointErrorV1::Binding);
        };
        let hkdf = Hkdf::<Sha256>::new(Some(DOMAIN), secret.as_bytes());
        let mut key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(digest, &mut *key)
            .map_err(|_| ThresholdBlsError::HkdfExpand)?;
        Ok(SymmetricEncryptor::new_with_key(&key[..])?)
    }
    /// Seal the original recipient, optional original polynomial and complete accepted set.
    ///
    /// All storage is already owned. Once encryption starts any failure is terminal;
    /// publication retries use [`Self::encrypted_record`] and never invoke this again.
    ///
    /// # Errors
    /// Refuses foreign bindings, phase/secret geometry, repeated production or real entropy failure.
    pub fn seal(
        &mut self,
        binding: &DkgCheckpointBindingV1,
        lifecycle: &KeyPair,
        recipient: &HybridKeyPair,
        dealer: Option<&DasRenDealerSecret<P>>,
        contributions: &[DasRenPrivateShare<P>],
    ) -> Result<(), DkgCheckpointErrorV1> {
        if self.terminal || self.binding.is_some() {
            return Err(DkgCheckpointErrorV1::Terminal);
        }
        let digest = self.context(binding, lifecycle)?;
        let seats = usize::from(self.parameters.session().committee_size());
        if (matches!(binding.phase, 1 | 2) && dealer.is_none())
            || (binding.phase == 3 && (dealer.is_some() || contributions.len() != seats))
            || (binding.phase != 3 && !contributions.is_empty())
        {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        if let Some(dealer) = dealer
            && (dealer.parameters_digest != self.parameters.digest()
                || dealer.session_id != *self.parameters.session().session_id()
                || dealer.dealer_index != self.seat_index)
        {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        for (index, share) in contributions.iter().enumerate() {
            if share.parameters_digest != self.parameters.digest()
                || share.recipient_index != self.seat_index
                || usize::from(share.dealer_index) != index + 1
            {
                return Err(DkgCheckpointErrorV1::Binding);
            }
        }
        let coefficient_count = dealer
            .map_or(Ok(0), |dealer| u16::try_from(dealer.coefficients.len()))
            .map_err(|_| DkgCheckpointErrorV1::Binding)?;
        let contribution_count =
            u16::try_from(contributions.len()).map_err(|_| DkgCheckpointErrorV1::Binding)?;
        self.destination.reset();
        let record = &mut self.destination.record.as_mut_slice()[0];
        record.version = 1;
        record.purpose = P::ROLE_TAG;
        record.parameters_digest = self.parameters.digest();
        record.seat_index = self.seat_index;
        let (x, kem) = recipient.secret().to_bytes();
        let x = Zeroizing::new(x);
        record.x25519_secret.copy_from_slice(&x[..]);
        record.mlkem768_secret.copy_from_slice(&kem[..]);
        if let Some(dealer) = dealer {
            record.coefficient_count = coefficient_count;
            for (index, coefficient) in dealer.coefficients.iter().enumerate() {
                for (component, bytes) in coefficient.iter().enumerate() {
                    let start = index * 96 + component * 32;
                    record.coefficients[start..start + 32].copy_from_slice(bytes);
                }
            }
        }
        record.contribution_count = contribution_count;
        for (index, share) in contributions.iter().enumerate() {
            for (component, bytes) in share.scalar_bytes.iter().enumerate() {
                let start = index * 96 + component * 32;
                record.contributions[start..start + 32].copy_from_slice(bytes);
            }
        }
        let len = self.work.0.as_slice().len();
        let encoded = {
            let mut output = &mut self.work.0.as_mut_slice()[12..len - 16];
            norito::core::write_canonical_to_writer(record, &mut output).and_then(|()| {
                if output.is_empty() {
                    Ok(())
                } else {
                    Err(norito::Error::LengthMismatch)
                }
            })
        };
        self.destination.reset();
        if let Err(error) = encoded {
            self.work.0.as_mut_slice().zeroize();
            return Err(error.into());
        }
        self.binding = Some(digest);
        self.terminal = true;
        let result = Self::cipher(lifecycle.private_key(), &digest).and_then(|cipher| {
            cipher
                .encrypt_easy_in_place(&digest[..], self.work.0.as_mut_slice())
                .map_err(DkgCheckpointErrorV1::from)
        });
        if let Err(error) = result {
            self.work.0.as_mut_slice().zeroize();
            return Err(error);
        }
        self.source
            .0
            .as_mut_slice()
            .copy_from_slice(self.work.0.as_slice());
        self.work.0.as_mut_slice().zeroize();
        self.sealed = true;
        Ok(())
    }
    /// Borrow only the immutable encrypted record after successful one-shot sealing.
    #[must_use]
    pub fn encrypted_record(&self) -> Option<&[u8]> {
        self.sealed.then(|| self.source.0.as_slice())
    }
    /// Borrow a sealed record only for the same complete original context and signer.
    ///
    /// # Errors
    /// Refuses a changed context or an unfinished original producer without RNG.
    pub fn encrypted_record_for(
        &self,
        binding: &DkgCheckpointBindingV1,
        lifecycle: &KeyPair,
    ) -> Result<&[u8], DkgCheckpointErrorV1> {
        let digest = self.context(binding, lifecycle)?;
        if self.binding != Some(digest) {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        self.encrypted_record()
            .ok_or(DkgCheckpointErrorV1::Terminal)
    }

    /// Restore against the exact original public recipient and proof-validated dealers.
    ///
    /// No RNG, Schnorr reproof, new capsule or signature is produced. The complete
    /// ciphertext/context is retained through a canonical decode refusal. Every
    /// failure clears private validity and zeroizes actual plaintext backing.
    ///
    /// # Errors
    /// Refuses replay/context/source changes, AEAD corruption, original codec failures,
    /// invalid secret geometry or any mismatch with the original checked public owners.
    pub fn restore(
        &mut self,
        encrypted: &[u8],
        binding: &DkgCheckpointBindingV1,
        lifecycle: &KeyPair,
        original_recipient: &HybridPublicKey,
        original_dealers: &[ValidatedDealerCommitment<P>],
        limits: norito::DecodeLimits,
    ) -> Result<(), DkgCheckpointErrorV1> {
        self.destination.reset();
        self.work.0.as_mut_slice().zeroize();
        self.restored_recipient = None;
        self.restored_dealer = None;
        self.restored_phase = 0;
        if let Some(shares) = self.shares.as_mut() {
            shares.truncate(0);
        }
        if self.terminal {
            return Err(DkgCheckpointErrorV1::Terminal);
        }
        let digest = self.context(binding, lifecycle)?;
        if encrypted.len() != self.source.0.as_slice().len() {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        let source_hash: [u8; 32] = Sha256::digest(encrypted).into();
        if self.binding.is_some_and(|old| old != digest)
            || self.source_hash.is_some_and(|old| old != source_hash)
        {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        self.binding = Some(digest);
        self.source_hash = Some(source_hash);
        self.source.0.as_mut_slice().copy_from_slice(encrypted);
        self.work
            .0
            .as_mut_slice()
            .copy_from_slice(self.source.0.as_slice());
        self.destination.reset();
        self.restored_recipient = None;
        self.restored_dealer = None;
        self.shares
            .as_mut()
            .ok_or(DkgCheckpointErrorV1::Terminal)?
            .truncate(0);
        let result = (|| {
            let plaintext = Self::cipher(lifecycle.private_key(), &digest)?
                .decrypt_easy_in_place(&digest[..], self.work.0.as_mut_slice())?;
            self.workspace.decode_canonical_into::<PrivateRecord, _>(
                plaintext,
                limits,
                &mut self.destination,
            )?;
            let record = &self.destination.record.as_slice()[0];
            let seats = usize::from(self.parameters.session().committee_size());
            let coefficient_count = usize::from(record.coefficient_count);
            let contribution_count = usize::from(record.contribution_count);
            if record.version != 1
                || record.purpose != P::ROLE_TAG
                || record.parameters_digest != self.parameters.digest()
                || record.seat_index != self.seat_index
                || (coefficient_count != 0
                    && coefficient_count != usize::from(self.parameters.session().threshold()))
                || (matches!(binding.phase, 1 | 2) && coefficient_count == 0)
                || (binding.phase == 3 && (coefficient_count != 0 || contribution_count != seats))
                || (binding.phase != 3 && contribution_count != 0)
                || !is_zero(&record.coefficients[coefficient_count * 96..])
                || !is_zero(&record.contributions[contribution_count * 96..])
            {
                return Err(DkgCheckpointErrorV1::Binding);
            }
            let recipient = HybridSecretKey::from_bytes(
                record.x25519_secret.as_slice(),
                record.mlkem768_secret.as_slice(),
            )?;
            let restored_public = recipient.public();
            if restored_public.x25519_bytes() != original_recipient.x25519_bytes()
                || restored_public.kyber_bytes() != original_recipient.kyber_bytes()
            {
                return Err(DkgCheckpointErrorV1::Binding);
            }
            let original_own = if binding.phase == 1 {
                if original_dealers.len() != 1
                    || original_dealers[0].dealer_index != self.seat_index
                    || original_dealers[0].parameters_digest != self.parameters.digest()
                {
                    return Err(DkgCheckpointErrorV1::Binding);
                }
                &original_dealers[0]
            } else {
                if original_dealers.len() != seats
                    || original_dealers.iter().enumerate().any(|(i, d)| {
                        usize::from(d.dealer_index) != i + 1
                            || d.parameters_digest != self.parameters.digest()
                    })
                {
                    return Err(DkgCheckpointErrorV1::Binding);
                }
                &original_dealers[usize::from(self.seat_index - 1)]
            };
            if coefficient_count != 0 {
                let mut coefficients =
                    Zeroizing::new([[[0_u8; 32]; 3]; MAX_DEALER_COEFFICIENTS_V1]);
                for (i, coefficient) in coefficients[..coefficient_count].iter_mut().enumerate() {
                    for (j, component) in coefficient.iter_mut().enumerate() {
                        component.copy_from_slice(
                            &record.coefficients[i * 96 + j * 32..i * 96 + (j + 1) * 32],
                        );
                    }
                }
                let coefficients =
                    DasRenSecretCoefficientsV1::new(coefficients, coefficient_count)?;
                self.restored_dealer = Some(restore_original_dealer(
                    &self.parameters,
                    original_own,
                    coefficients,
                )?);
            }
            for (i, dealer) in original_dealers[..contribution_count].iter().enumerate() {
                let mut parts = Zeroizing::new([[0_u8; 32]; 3]);
                for (j, part) in parts.iter_mut().enumerate() {
                    part.copy_from_slice(
                        &record.contributions[i * 96 + j * 32..i * 96 + (j + 1) * 32],
                    );
                }
                let share = DasRenPrivateShare::from_components(
                    &self.parameters,
                    dealer,
                    self.seat_index,
                    parts[0],
                    parts[1],
                    parts[2],
                )?;
                self.shares
                    .as_mut()
                    .ok_or(DkgCheckpointErrorV1::Terminal)?
                    .push_reserved(share);
            }
            self.restored_recipient = Some(HybridKeyPair::from_checkpoint_secret(recipient));
            Ok(())
        })();
        self.work.0.as_mut_slice().zeroize();
        self.destination.reset();
        if result.is_ok() {
            self.restored_phase = binding.phase;
            self.sealed = true;
        } else {
            self.restored_recipient = None;
            self.restored_dealer = None;
            if let Some(shares) = self.shares.as_mut() {
                shares.truncate(0);
            }
        }
        result
    }
    /// Move only successfully restored generation owners while retaining original ciphertext.
    ///
    /// The empty accepted-share backing and exact encrypted head remain prepaid in
    /// this bank for the next phase's chain. This does not generate, reprove, sign,
    /// copy a secret or admit a replacement buffer. It is deliberately restricted
    /// to generation; later phase graph restoration has a separate owner boundary.
    ///
    /// # Errors
    /// Rejects unfinished, non-generation or already extracted restored owners.
    pub fn take_restored_generation_owners(
        &mut self,
    ) -> Result<(HybridKeyPair, DasRenDealerSecret<P>), DkgCheckpointErrorV1> {
        self.take_restored_polynomial_owners(1)
    }

    /// Move the original delivered recipient and polynomial after complete phase-two restore.
    ///
    /// The original encrypted head and empty share backing remain in this bank.
    /// The enclosing seat must retain the polynomial until its daemon establishes
    /// the original output's file and directory durability; this method neither
    /// certifies that boundary nor permits a fresh capsule or signature.
    ///
    /// # Errors
    /// Refuses unfinished, foreign-phase or already moved original owners.
    pub fn take_restored_delivery_owners(
        &mut self,
    ) -> Result<(HybridKeyPair, DasRenDealerSecret<P>), DkgCheckpointErrorV1> {
        self.take_restored_polynomial_owners(2)
    }

    fn take_restored_polynomial_owners(
        &mut self,
        phase: u16,
    ) -> Result<(HybridKeyPair, DasRenDealerSecret<P>), DkgCheckpointErrorV1> {
        if self.terminal
            || self.restored_phase != phase
            || !self.sealed
            || self.restored_recipient.is_none()
            || self.restored_dealer.is_none()
            || !self
                .shares
                .as_ref()
                .is_some_and(|shares| shares.as_slice().is_empty())
        {
            return Err(DkgCheckpointErrorV1::Terminal);
        }
        self.terminal = true;
        self.restored_phase = 0;
        Ok((
            self.restored_recipient
                .take()
                .expect("checked restored recipient"),
            self.restored_dealer
                .take()
                .expect("checked original polynomial"),
        ))
    }

    /// Exchange complete accepted contributions with the enclosing seat's prepaid empty bank.
    ///
    /// Both allocations must belong to the exact same supplied pool and retain
    /// exactly `n` physical slots. The original contribution allocation moves to
    /// the seat; its empty replacement moves here with its unchanged charge. The
    /// ciphertext remains available for the authenticated head chain. No share
    /// copy, allocation, refund, entropy or signing occurs.
    ///
    /// # Errors
    /// Refuses incomplete/consumed phase-three state, foreign custody, nonempty
    /// replacement backing or a changed capacity before either allocation moves.
    pub fn take_restored_accepted_owners(
        &mut self,
        replacement: &mut ChargedBuffer<DasRenPrivateShare<P>>,
        budget: &AllocationBudget,
    ) -> Result<HybridKeyPair, DkgCheckpointErrorV1> {
        let seats = usize::from(self.parameters.session().committee_size());
        if self.terminal
            || self.restored_phase != 3
            || !self.sealed
            || self.restored_recipient.is_none()
            || self.restored_dealer.is_some()
        {
            return Err(DkgCheckpointErrorV1::Terminal);
        }
        if !self.belongs_to(budget)
            || !replacement.belongs_to(budget)
            || replacement.capacity() != seats
            || !replacement.as_slice().is_empty()
            || !self.shares.as_ref().is_some_and(|shares| {
                shares.capacity() == seats && shares.as_slice().len() == seats
            })
        {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        std::mem::swap(
            self.shares
                .as_mut()
                .expect("checked restored share backing"),
            replacement,
        );
        self.terminal = true;
        self.restored_phase = 0;
        Ok(self
            .restored_recipient
            .take()
            .expect("checked restored recipient"))
    }

    /// Check one restored contribution against its original authenticated capsule plaintext.
    ///
    /// The caller decrypts the original signed edge through the existing primitive;
    /// this comparison exposes no plaintext and moves no owner. Equal public
    /// polynomial equations alone do not substitute for the original ciphertext.
    ///
    /// # Errors
    /// Refuses unfinished/consumed accepted state or any changed original private component.
    pub fn verify_restored_accepted_contribution(
        &self,
        index: usize,
        original: &DasRenPrivateShare<P>,
    ) -> Result<(), DkgCheckpointErrorV1> {
        use subtle::ConstantTimeEq as _;
        if self.terminal || self.restored_phase != 3 || !self.sealed {
            return Err(DkgCheckpointErrorV1::Terminal);
        }
        let restored = self
            .shares
            .as_ref()
            .and_then(|shares| shares.as_slice().get(index))
            .ok_or(DkgCheckpointErrorV1::Binding)?;
        let mut equal = true;
        for (restored, original) in restored
            .scalar_bytes
            .iter()
            .zip(original.scalar_bytes.iter())
        {
            equal &= bool::from(restored.ct_eq(original));
        }
        if restored.parameters_digest != original.parameters_digest
            || restored.dealer_index != original.dealer_index
            || restored.recipient_index != original.recipient_index
            || !equal
        {
            return Err(DkgCheckpointErrorV1::Binding);
        }
        Ok(())
    }

    /// Move checked opaque secret owners, retiring original ciphertext/scratch storage.
    ///
    /// # Errors
    /// An unfinished owner is returned unchanged; no charge is replaced or refunded.
    #[allow(
        clippy::result_large_err,
        reason = "an unfinished extraction returns the original prepaid secret owner without allocating or refunding its backings"
    )]
    pub fn finish(mut self) -> Result<RestoredDkgSecretsV1<P>, Self> {
        let Some(recipient) = self.restored_recipient.take() else {
            return Err(self);
        };
        let Some(contributions) = self.shares.take() else {
            self.restored_recipient = Some(recipient);
            return Err(self);
        };
        Ok(RestoredDkgSecretsV1 {
            recipient,
            dealer: self.restored_dealer.take(),
            contributions,
        })
    }
}

// The caller supplied the existing, unforgeable verified dealer proof. Check the
// original equations and construct the same polynomial owner without RNG/reproof.
fn restore_original_dealer<P: ThresholdBlsPurpose>(
    parameters: &AdaptiveThresholdBlsParameters<P>,
    original: &ValidatedDealerCommitment<P>,
    coefficients: DasRenSecretCoefficientsV1,
) -> Result<DasRenDealerSecret<P>, ThresholdBlsError> {
    validate_participant_index(parameters.session(), original.dealer_index)?;
    if original.parameters_digest != parameters.digest()
        || coefficients.len() != original.coefficients.len()
        || coefficients.len() != usize::from(parameters.session().threshold())
    {
        return Err(ThresholdBlsError::SessionMismatch);
    }
    let zero = Scalar::from(0_u64).to_bytes_be();
    if coefficients[0][1] != zero
        || coefficients[0][2] != zero
        || decode_scalar(&coefficients[0][0])? == Scalar::from(0_u64)
    {
        return Err(ThresholdBlsError::InvalidCoefficientCommitment);
    }
    let h = G2Projective::from(parameters.h_point()?);
    let v = G2Projective::from(parameters.v_point()?);
    for (coefficient, commitment) in coefficients.iter().zip(&original.coefficients) {
        let point = G2Projective::generator() * decode_scalar(&coefficient[0])?
            + h * decode_scalar(&coefficient[1])?
            + v * decode_scalar(&coefficient[2])?;
        if bool::from(point.is_identity())
            || point.to_affine().to_compressed() != *commitment.as_bytes()
        {
            return Err(ThresholdBlsError::InvalidCoefficientCommitment);
        }
    }
    Ok(DasRenDealerSecret {
        parameters_digest: parameters.digest(),
        session_id: *parameters.session().session_id(),
        dealer_index: original.dealer_index,
        coefficients,
        marker: PhantomData,
    })
}

#[cfg(test)]
mod tests;
