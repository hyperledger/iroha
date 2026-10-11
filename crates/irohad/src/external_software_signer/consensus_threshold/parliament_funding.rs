//! Original-pool backing for Parliament's sole canonical credential field walk.
//!
//! This owner funds the decoded handle and Vec graph, its charge ledger, and
//! the prepared decoder controls. It does not fund supervisor input, the
//! enclosing std Arc controls, or Core's custody-map nodes. The private backend
//! retains the original graph's charges through its final reader; graph moves
//! never clone, grow, or export that backing.

use super::*;
use iroha_allocation::{AllocationCharge, ChargedBuffer, ChargedBufferError};
use iroha_core::beacon::credential::{
    MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1, consensus_threshold_credential_decode_limits_v1,
};
use iroha_core_timed_ovn::tle::{TleAdaptiveDealerCommitmentV1, TleAdaptivePublicShareV1};
use iroha_crypto::threshold_bls::{
    MAX_DEALER_COEFFICIENTS_V1, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1,
};
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeRecordFields, Encoder,
    FieldDestination, PayloadRef, PreparedDecodeError, PreparedDecodeScopeError,
    PreparedDecodeWorkspace, PreparedRecordDestination, SequenceDestinationError, SequenceSpan,
    SerializePayload, prepare_element_sequence,
};
use std::mem::ManuallyDrop;

const SEATS: usize = THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize;
// One handle, one outer session bank, and three public banks plus one
// coefficient bank per dealer. This is actual fixed ledger capacity, not an
// estimate of decoded graph bytes or a substitute allocation-pool limit.
const LEDGER_CAPACITY: usize = 2 + MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1 * (3 + SEATS);

#[cfg(test)]
pub(super) fn preparation_bytes() -> usize {
    std::alloc::Layout::array::<AllocationCharge>(LEDGER_CAPACITY)
        .unwrap()
        .size()
        + PreparedDecodeWorkspace::allocation_layouts()
            .iter()
            .map(std::alloc::Layout::size)
            .sum::<usize>()
}

/// Local failure constructing original-pool Parliament credential backing.
///
/// The exact original admission/allocator/control cause remains available;
/// display never includes a handle, session, scalar, credential, or source path.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeParliamentTleCredentialFundingErrorV1 {
    /// The original pool or physical allocator refused one exact backing layout.
    #[error("Parliament credential backing is unavailable")]
    Storage(#[source] ChargedBufferError),
    /// The original prepared decoder controls could not be constructed or entered.
    #[error("Parliament credential decoder controls are unavailable")]
    Scope(#[source] PreparedDecodeScopeError),
}
impl From<ChargedBufferError> for RuntimeParliamentTleCredentialFundingErrorV1 {
    fn from(error: ChargedBufferError) -> Self {
        Self::Storage(error)
    }
}
type FundingError = RuntimeParliamentTleCredentialFundingErrorV1;
type FieldResult<T> = Result<T, DecodeIntoError<FundingError>>;

struct Ledger(ChargedBuffer<AllocationCharge>);
impl Ledger {
    fn new(budget: &AllocationBudget) -> Result<Self, FundingError> {
        Ok(Self(ChargedBuffer::new(LEDGER_CAPACITY, budget)?))
    }

    #[allow(unsafe_code)]
    fn retain<T>(&mut self, buffer: ChargedBuffer<T>) -> Vec<T> {
        assert!(self.0.as_slice().len() < self.0.capacity());
        // SAFETY: every caller immediately moves this fixed Vec into a private
        // destination/owner. No capacity-changing operation or escaping clone
        // is available. The destination is destroyed before this ledger, on
        // all ordinary failures. FundedOwner conservatively keeps the ledger
        // if final payload destruction or a consuming transition unwinds.
        let (values, charge) = unsafe { buffer.into_allocation_parts() };
        self.0.push_reserved(charge);
        values
    }
}

/// Move-only custody of precisely the decoded allocations, without extraction.
/// Additional service/control allocations remain separate, explicit obligations.
pub(super) struct FundedOwner<T> {
    payload: ManuallyDrop<T>,
    ledger: ManuallyDrop<Ledger>,
}
impl<T> FundedOwner<T> {
    pub(super) fn get(&self) -> &T {
        &self.payload
    }

    /// Consume the private DTO into its private runtime owner. Mapping may
    /// destroy temporary outer backing but cannot grow, clone, or export a
    /// funded nested allocation. Its credit is conservatively retained.
    #[allow(unsafe_code)]
    pub(super) fn try_map<U, E>(
        self,
        map: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<FundedOwner<U>, E> {
        let mut original = ManuallyDrop::new(self);
        // SAFETY: the original no longer runs Drop. The private synchronous
        // importer consumes exactly one DTO; ledger custody spans its unwind.
        let payload = unsafe { ManuallyDrop::take(&mut original.payload) };
        match map(payload) {
            Ok(payload) => Ok(FundedOwner {
                payload: ManuallyDrop::new(payload),
                // SAFETY: the mapper returned with the original surviving
                // allocations moved only into the returned private backend.
                ledger: ManuallyDrop::new(unsafe { ManuallyDrop::take(&mut original.ledger) }),
            }),
            Err(error) => {
                // SAFETY: the importer destroyed its complete private DTO and
                // any partially built custody before returning this error.
                unsafe { ManuallyDrop::drop(&mut original.ledger) };
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.ledger.0.belongs_to(budget)
            && self
                .ledger
                .0
                .as_slice()
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
}
impl<T> Drop for FundedOwner<T> {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: this is the sole private owner of the funded graph. A normal
        // return proves complete payload reclamation; on unwind the ledger is
        // retained rather than refunding any possibly live physical allocation.
        unsafe { ManuallyDrop::drop(&mut self.payload) };
        // SAFETY: all funded backing was destroyed exactly once above.
        unsafe { ManuallyDrop::drop(&mut self.ledger) };
    }
}

fn complete(used: usize, bytes: &[u8]) -> FieldResult<()> {
    if used != bytes.len() {
        return Err(norito::Error::LengthMismatch.into());
    }
    Ok(())
}
// Direct byte-array record fields carry the constructor-selected raw codec.
// Generic array sequence elements continue through `fixed` below.
fn raw<const N: usize>(field: CanonicalField<'_, [u8; N]>) -> FieldResult<[u8; N]> {
    field.decode_owned().map_err(DecodeIntoError::Codec)
}

fn fixed<T>(field: CanonicalField<'_, T>) -> FieldResult<T>
where
    for<'a> T: DecodeFromSlice<'a>,
{
    field.with_payload(|bytes| {
        let (value, used) = T::decode_from_slice(bytes)?;
        complete(used, bytes)?;
        Ok(value)
    })
}

fn sequence<T, const N: usize>(
    field: CanonicalField<'_, Vec<T>>,
    budget: &AllocationBudget,
    ledger: &mut Ledger,
    mut decode: impl FnMut(CanonicalField<'_, T>, &AllocationBudget, &mut Ledger) -> FieldResult<T>,
) -> FieldResult<Vec<T>>
where
    T: for<'a> norito::DeserializePayload<'a> + SerializePayload,
{
    field.with_payload(|bytes| {
        let mut spans = [SequenceSpan { start: 0, end: 0 }; N];
        let plan = prepare_element_sequence(bytes, &mut spans).map_err(|error| match error {
            SequenceDestinationError::Codec(error) => DecodeIntoError::Codec(error),
            // N is the existing normative session/committee/degree bound.
            // No accepted credential can require a larger destination.
            SequenceDestinationError::Storage { .. } => {
                DecodeIntoError::Codec(norito::Error::InvalidValue {
                    context: "invalid Parliament credential cardinality",
                })
            }
        })?;
        complete(plan.used(), bytes)?;
        let mut values = ChargedBuffer::new(plan.len(), budget)
            .map_err(|error| DecodeIntoError::Destination(error.into()))?;
        plan.decode_elements::<T, FundingError>(|_, field| {
            values.push_reserved(decode(field, budget, ledger)?);
            Ok(())
        })?;
        Ok(ledger.retain(values))
    })
}

fn string(
    field: CanonicalField<'_, String>,
    budget: &AllocationBudget,
    ledger: &mut Ledger,
) -> FieldResult<String> {
    field.with_payload(|bytes| {
        let (source, used) = <&str as DecodeFromSlice>::decode_from_slice(bytes)?;
        // The shared length reader already admits the ordinary String leaf's
        // logical work once. Physical backing admission remains separate below.
        complete(used, bytes)?;
        let mut values = ChargedBuffer::new(source.len(), budget)
            .map_err(|error| DecodeIntoError::Destination(error.into()))?;
        for byte in source.as_bytes() {
            values.push_reserved(*byte);
        }
        let values = ledger.retain(values);
        // Original UTF-8 was checked before allocating; conversion neither
        // allocates nor changes the retained Vec's capacity or physical layout.
        Ok(String::from_utf8(values).expect("prevalidated original UTF-8"))
    })
}

macro_rules! destination {
    ($name:ident, $wire:ident, { $($index:literal => $field:ident : $ty:ty = $decode:expr),* $(,)? }) => {
        struct $name<'a> {
            budget: &'a AllocationBudget,
            ledger: &'a mut Ledger,
            $($field: Option<$ty>,)*
        }
        impl<'a> $name<'a> {
            fn new(budget: &'a AllocationBudget, ledger: &'a mut Ledger) -> Self {
                Self { budget, ledger, $($field: None,)* }
            }
            fn finish(self) -> FieldResult<$wire> {
                Ok($wire { $($field: self.$field.ok_or(norito::Error::LengthMismatch)?,)* })
            }
        }
        impl FieldDestination for $name<'_> { type Error = FundingError; }
        $(impl DecodeField<$index, $ty> for $name<'_> {
            type Value = ();
            fn decode_field(&mut self, field: CanonicalField<'_, $ty>) -> FieldResult<()> {
                self.$field = Some(($decode)(field, self.budget, &mut *self.ledger)?);
                Ok(())
            }
        })*
    };
}

// Scalars and byte arrays use canonical slice leaves directly, with no lazy
// owned alignment copy. Every nested record uses its generated sole field walk.
fn key_session(
    field: CanonicalField<'_, iroha_data_model::governance::types::TleKeySessionId>,
) -> FieldResult<iroha_data_model::governance::types::TleKeySessionId> {
    iroha_data_model::governance::types::TleKeySessionId::decode_prepared_field_v1(field).map_err(
        |error| match error {
            DecodeIntoError::Codec(error) => DecodeIntoError::Codec(error),
            DecodeIntoError::Destination(never) => match never {},
        },
    )
}

fn components(
    field: CanonicalField<'_, ConsensusThresholdSecretScalarTripleV1>,
) -> FieldResult<ConsensusThresholdSecretScalarTripleV1> {
    struct Scalars(Option<Zeroizing<[[u8; 32]; 3]>>);
    impl FieldDestination for Scalars {
        type Error = FundingError;
    }
    impl DecodeField<0, [[u8; 32]; 3]> for Scalars {
        type Value = ();
        fn decode_field(&mut self, field: CanonicalField<'_, [[u8; 32]; 3]>) -> FieldResult<()> {
            self.0 = Some(Zeroizing::new(fixed(field)?));
            Ok(())
        }
    }
    field.with_payload(|bytes| {
        let mut scalars = Scalars(None);
        let (_, used) = ConsensusThresholdSecretScalarTripleV1::decode_fields(bytes, &mut scalars)?;
        complete(used, bytes)?;
        Ok(ConsensusThresholdSecretScalarTripleV1::from_zeroizing(
            scalars.0.ok_or(norito::Error::LengthMismatch)?,
        ))
    })
}

destination!(Header, ConsensusThresholdCredentialHeaderV1, {
    0 => magic: [u8; 8] = |f, _, _| raw(f),
    1 => version: u16 = |f, _, _| fixed(f),
    2 => slot: u16 = |f, _, _| fixed(f),
    3 => network_id: NetworkId = |f, _, _| fixed(f),
    4 => handle: String = string,
    5 => revision: u64 = |f, _, _| fixed(f),
    6 => policy_digest: [u8; 32] = |f, _, _| raw(f),
});
destination!(Dealer, TleAdaptiveDealerCommitmentV1, {
    0 => dealer_index: u16 = |f, _, _| fixed(f),
    1 => coefficient_commitments: Vec<[u8; 96]> = |f, b, l| sequence::<_, MAX_DEALER_COEFFICIENTS_V1>(f, b, l, |f, _, _| fixed(f)),
    2 => constant_pok_commitment: [u8; 96] = |f, _, _| raw(f),
    3 => constant_pok_response: [u8; 32] = |f, _, _| raw(f),
});
destination!(PublicShare, TleAdaptivePublicShareV1, {
    0 => index: u16 = |f, _, _| fixed(f),
    1 => participant_hash: [u8; 32] = |f, _, _| raw(f),
    2 => public_key_share: [u8; 96] = |f, _, _| raw(f),
});
destination!(State, TleKeySessionPublicStateV1, {
    0 => version: u16 = |f, _, _| fixed(f),
    1 => key_session_id: iroha_data_model::governance::types::TleKeySessionId = |f, _, _| key_session(f),
    2 => network_id: [u8; 32] = |f, _, _| raw(f),
    3 => roster_hash: [u8; 32] = |f, _, _| raw(f),
    4 => committee_size: u16 = |f, _, _| fixed(f),
    5 => threshold: u16 = |f, _, _| fixed(f),
    6 => generator_h: [u8; 96] = |f, _, _| raw(f),
    7 => generator_v: [u8; 96] = |f, _, _| raw(f),
    8 => qualified_dealers: Vec<u16> = |f, b, l| sequence::<_, SEATS>(f, b, l, |f, _, _| fixed(f)),
    9 => qualified_dealer_commitments: Vec<TleAdaptiveDealerCommitmentV1> = |f, b, l| sequence::<_, SEATS>(f, b, l, decode_dealer),
    10 => dkg_event_hash: [u8; 32] = |f, _, _| raw(f),
    11 => group_public_key: [u8; 96] = |f, _, _| raw(f),
    12 => public_shares: Vec<TleAdaptivePublicShareV1> = |f, b, l| sequence::<_, SEATS>(f, b, l, decode_public_share),
    13 => transcript_hash: [u8; 32] = |f, _, _| raw(f),
});
destination!(Share, RuntimeParliamentTleShareCredentialWireV1, {
    0 => public_session: TleKeySessionPublicStateV1 = decode_state,
    1 => participant_index: u16 = |f, _, _| fixed(f),
    2 => components: ConsensusThresholdSecretScalarTripleV1 = |f, _, _| components(f),
});

macro_rules! decode_record {
    ($function:ident, $destination:ident, $wire:ty) => {
        fn $function(
            field: CanonicalField<'_, $wire>,
            budget: &AllocationBudget,
            ledger: &mut Ledger,
        ) -> FieldResult<$wire> {
            field.with_payload(|bytes| {
                let mut destination = $destination::new(budget, ledger);
                let (_, used) = <$wire>::decode_fields(bytes, &mut destination)?;
                complete(used, bytes)?;
                destination.finish()
            })
        }
    };
}
decode_record!(decode_header, Header, ConsensusThresholdCredentialHeaderV1);
decode_record!(decode_dealer, Dealer, TleAdaptiveDealerCommitmentV1);
decode_record!(decode_public_share, PublicShare, TleAdaptivePublicShareV1);
decode_record!(decode_state, State, TleKeySessionPublicStateV1);
decode_record!(
    decode_share,
    Share,
    RuntimeParliamentTleShareCredentialWireV1
);

struct Credential<'a> {
    budget: &'a AllocationBudget,
    ledger: &'a mut Ledger,
    header: Option<ConsensusThresholdCredentialHeaderV1>,
    sessions: Option<Vec<RuntimeParliamentTleShareCredentialWireV1>>,
    valid: bool,
}
impl FieldDestination for Credential<'_> {
    type Error = FundingError;
}
impl DecodeField<0, ConsensusThresholdCredentialHeaderV1> for Credential<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, ConsensusThresholdCredentialHeaderV1>,
    ) -> FieldResult<()> {
        self.header = Some(decode_header(field, self.budget, self.ledger)?);
        Ok(())
    }
}
impl DecodeField<1, Vec<RuntimeParliamentTleShareCredentialWireV1>> for Credential<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Vec<RuntimeParliamentTleShareCredentialWireV1>>,
    ) -> FieldResult<()> {
        self.sessions = Some(
            sequence::<_, MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1>(
                field,
                self.budget,
                self.ledger,
                decode_share,
            )?,
        );
        self.valid = self.header.is_some();
        Ok(())
    }
}
impl SerializePayload for Credential<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(NoritoSerialize)]
        struct View<'a> {
            header: PayloadRef<'a, ConsensusThresholdCredentialHeaderV1>,
            sessions: PayloadRef<'a, Vec<RuntimeParliamentTleShareCredentialWireV1>>,
        }
        if !self.valid {
            return Err(norito::Error::LengthMismatch);
        }
        View {
            header: PayloadRef(self.header.as_ref().ok_or(norito::Error::LengthMismatch)?),
            sessions: PayloadRef(
                self.sessions
                    .as_ref()
                    .ok_or(norito::Error::LengthMismatch)?,
            ),
        }
        .serialize(writer)
    }
}
impl PreparedRecordDestination<RuntimeParliamentTleSignerCredentialWireV1> for Credential<'_> {
    fn reset(&mut self) {
        // Preserve all filled backing until this original attempt's destination
        // is retired. Neither invalidity nor canonical mismatch refunds early.
        self.valid = false;
    }
}

pub(super) fn decode(
    bytes: &[u8],
    budget: &AllocationBudget,
) -> Result<
    FundedOwner<RuntimeParliamentTleSignerCredentialWireV1>,
    RuntimeConsensusThresholdSignerCredentialErrorV1,
> {
    if bytes.is_empty() || bytes.len() > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1 {
        return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
    }
    let mut reservation = budget
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .map_err(|error| {
            RuntimeConsensusThresholdSignerCredentialErrorV1::ParliamentFunding(
                FundingError::Storage(error.into()),
            )
        })?;
    let mut workspace = PreparedDecodeWorkspace::from_reservation(budget, &mut reservation)
        .map_err(|error| {
            RuntimeConsensusThresholdSignerCredentialErrorV1::ParliamentFunding(
                FundingError::Scope(error),
            )
        })?;
    let mut ledger = Ledger::new(budget)
        .map_err(RuntimeConsensusThresholdSignerCredentialErrorV1::ParliamentFunding)?;
    let mut destination = Credential {
        budget,
        ledger: &mut ledger,
        header: None,
        sessions: None,
        valid: false,
    };
    workspace
        .decode_canonical_into::<RuntimeParliamentTleSignerCredentialWireV1, _>(
            bytes,
            consensus_threshold_credential_decode_limits_v1(bytes.len()),
            &mut destination,
        )
        .map_err(|error| match error {
            PreparedDecodeError::Codec(error) => match error.kind() {
                norito::core::DecodeAttemptErrorKind::Invalid => {
                    RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected
                }
                norito::core::DecodeAttemptErrorKind::EnclosingLimit
                | norito::core::DecodeAttemptErrorKind::Allocator => {
                    RuntimeConsensusThresholdSignerCredentialErrorV1::DecodeResource(error)
                }
            },
            PreparedDecodeError::Destination(error) => {
                RuntimeConsensusThresholdSignerCredentialErrorV1::ParliamentFunding(error)
            }
            PreparedDecodeError::Scope(error) => {
                RuntimeConsensusThresholdSignerCredentialErrorV1::ParliamentFunding(
                    FundingError::Scope(error),
                )
            }
        })?;
    let payload = RuntimeParliamentTleSignerCredentialWireV1 {
        header: destination
            .header
            .take()
            .ok_or(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)?,
        sessions: destination
            .sessions
            .take()
            .ok_or(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)?,
    };
    drop(destination);
    Ok(FundedOwner {
        payload: ManuallyDrop::new(payload),
        ledger: ManuallyDrop::new(ledger),
    })
}

#[cfg(test)]
mod owner_tests {
    use super::*;

    fn original_owner(pool: &AllocationBudget) -> FundedOwner<Vec<u8>> {
        let mut ledger = Ledger::new(pool).unwrap();
        let mut bytes = ChargedBuffer::new(3, pool).unwrap();
        for byte in [1, 2, 3] {
            bytes.push_reserved(byte);
        }
        FundedOwner {
            payload: ManuallyDrop::new(ledger.retain(bytes)),
            ledger: ManuallyDrop::new(ledger),
        }
    }

    #[test]
    fn prepared_string_preserves_ordinary_leaf_logical_admission_at_exact_boundary() {
        let source = "abc";
        let mut payload = Vec::new();
        norito::core::serialize_to_writer(&source, &mut payload).unwrap();
        for allowed in [source.len() - 1, source.len()] {
            let limits = norito::core::DecodeLimits::new(16, 64, 64, allowed, 64);
            let ordinary =
                norito::with_decode_limits_scope(limits, || String::decode_from_slice(&payload));
            let mut framed = Vec::new();
            norito::core::write_len_with_flags(
                &mut framed,
                payload.len() as u64,
                norito::core::default_encode_flags(),
            )
            .unwrap();
            framed.extend_from_slice(&payload);
            let field = norito::core::framed_field::<String>(&framed, &mut 0).unwrap();
            let pool = AllocationBudget::new(1024 * 1024);
            let mut ledger = Ledger::new(&pool).unwrap();
            let prepared =
                norito::with_decode_limits_scope(limits, || string(field, &pool, &mut ledger));
            assert_eq!(ordinary.is_ok(), prepared.is_ok());
            if allowed == source.len() {
                assert_eq!(ordinary.unwrap().0, source);
                assert_eq!(prepared.as_ref().unwrap(), source);
                assert_eq!(
                    pool.reserved_bytes(),
                    preparation_bytes()
                        - PreparedDecodeWorkspace::allocation_layouts()
                            .iter()
                            .map(std::alloc::Layout::size)
                            .sum::<usize>()
                        + source.len()
                );
            } else {
                let ordinary = ordinary.err().unwrap();
                let DecodeIntoError::Codec(prepared) = prepared.as_ref().err().unwrap() else {
                    panic!("same original logical refusal");
                };
                assert_eq!(
                    ordinary.decode_resource_error(),
                    prepared.decode_resource_error()
                );
            }
            drop(prepared);
            drop(ledger);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }

    #[test]
    fn consuming_semantic_failure_reclaims_actual_payload_before_original_ledger_refund() {
        let pool = AllocationBudget::new(1024 * 1024);
        let owner = original_owner(&pool);
        assert!(owner.belongs_to(&pool));
        assert!(pool.reserved_bytes() > 0);
        let error = owner
            .try_map::<Vec<u8>, _>(|bytes| {
                assert_eq!(bytes, [1, 2, 3]);
                drop(bytes);
                assert!(
                    pool.reserved_bytes() > 0,
                    "physical graph retirement alone does not refund the ledger"
                );
                Err("semantic rejection")
            })
            .err()
            .unwrap();
        assert_eq!(error, "semantic rejection");
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn consuming_unwind_cannot_publish_unproven_graph_reclamation_as_available_credit() {
        let pool = AllocationBudget::new(1024 * 1024);
        let owner = original_owner(&pool);
        let retained = pool.reserved_bytes();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<FundedOwner<Vec<u8>>, ()> =
                owner.try_map(|_bytes| panic!("private importer unwound"));
        }));
        assert!(unwind.is_err());
        // As in RetainedPayload, an unproven consuming unwind conservatively
        // retains the actual original ledger allocation and charges. No new
        // pool or replacement capacity is fabricated by the failed transition.
        assert_eq!(pool.reserved_bytes(), retained);
    }
}

#[cfg(test)]
mod raw_field_adapter_tests {
    use super::*;

    fn check_raw_record<const N: usize, E: std::fmt::Debug>(
        value: &impl SerializePayload,
        raw_indices: &[usize],
        start: usize,
        raw_only: bool,
        mut decode: impl FnMut(&[u8]) -> std::result::Result<usize, DecodeIntoError<E>>,
    ) {
        let mut payload = Vec::new();
        norito::core::serialize_to_writer(value, &mut payload).unwrap();
        let original = consensus_threshold_credential_decode_limits_v1(payload.len());
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(original, || decode(&payload));
        assert_eq!(decoded.unwrap(), payload.len());
        let required = usage.total_allocated_bytes();
        if raw_only {
            assert_eq!(required, 0);
        } else {
            // Borrowed strings and generic coefficient sequences retain their
            // legitimate logical charges; raw byte fields add no storage charge.
            assert!(required > 0);
        }
        let limits = norito::DecodeLimits::new(
            16_384,
            original.max_field_bytes(),
            original.max_total_elements(),
            required,
            64,
        );
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(limits, || decode(&payload));
        assert_eq!(decoded.unwrap(), payload.len());
        assert_eq!(usage.total_allocated_bytes(), required);
        if required > 0 {
            let short = norito::DecodeLimits::new(
                16_384,
                original.max_field_bytes(),
                original.max_total_elements(),
                required - 1,
                64,
            );
            let (decoded, _) =
                norito::core::with_decode_limits_measured(short, || decode(&payload));
            assert!(matches!(
                decoded,
                Err(DecodeIntoError::Codec(
                    norito::Error::TotalAllocationExceeded { .. }
                ))
            ));
        }
        for &index in raw_indices {
            let mut offset = start;
            let mut frame_start = 0;
            let mut body_start = 0;
            for _ in 0..=index {
                frame_start = offset;
                let (length, prefix) =
                    norito::core::inspect_len_from_slice(&payload[offset..]).unwrap();
                body_start = offset + prefix;
                offset = body_start + length;
            }
            let raw: [u8; N] = payload[body_start..offset].try_into().unwrap();
            let mut generic = Vec::new();
            norito::core::serialize_to_writer(&raw, &mut generic).unwrap();
            assert_ne!(generic.len(), N);
            let mut long = raw.to_vec();
            long.push(0xa5);
            for body in [raw[..N - 1].to_vec(), long, generic] {
                let mut malformed = payload[..frame_start].to_vec();
                norito::core::write_len_header_to_vec(&mut malformed, body.len() as u64);
                malformed.extend_from_slice(&body);
                malformed.extend_from_slice(&payload[offset..]);
                let actual = consensus_threshold_credential_decode_limits_v1(malformed.len());
                let malformed_limits = norito::DecodeLimits::new(
                    16_384,
                    actual.max_field_bytes(),
                    actual.max_total_elements(),
                    required,
                    64,
                );
                let (decoded, usage) =
                    norito::core::with_decode_limits_measured(malformed_limits, || {
                        decode(&malformed)
                    });
                assert!(matches!(
                    decoded,
                    Err(DecodeIntoError::Codec(norito::Error::LengthMismatch))
                ));
                assert!(usage.total_allocated_bytes() <= required);
            }
        }
    }

    fn hash(seed: u8) -> [u8; 32] {
        std::array::from_fn(|i| (i as u8).wrapping_add(seed))
    }

    #[test]
    fn parliament_raw_fields_keep_both_layouts_generic_coefficients_and_exact_retirement() {
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let header = ConsensusThresholdCredentialHeaderV1 {
                magic: *b"IRTHR001",
                version: 1,
                slot: 1,
                network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                    iroha_data_model::block::BlockHeader,
                >::from_untyped_unchecked(
                    iroha_crypto::Hash::prehashed(hash(0x11)),
                )),
                handle: "software://iroha/raw-field-test".into(),
                revision: 7,
                policy_digest: hash(0x21),
            };
            let pool = AllocationBudget::new(1 << 20);
            let mut decode_header = |bytes: &[u8]| {
                let result = {
                    let mut ledger = Ledger::new(&pool).unwrap();
                    let mut destination = Header::new(&pool, &mut ledger);
                    ConsensusThresholdCredentialHeaderV1::decode_fields(bytes, &mut destination)
                        .map(|(_, used)| {
                            let decoded = destination.finish().unwrap();
                            assert_eq!(decoded, header);
                            drop(decoded);
                            used
                        })
                };
                assert_eq!(pool.reserved_bytes(), 0);
                result
            };
            check_raw_record::<8, _>(&header, &[0], 0, false, &mut decode_header);
            check_raw_record::<32, _>(&header, &[6], 0, false, &mut decode_header);
            let dealer = TleAdaptiveDealerCommitmentV1 {
                dealer_index: 3,
                coefficient_commitments: vec![
                    std::array::from_fn(|i| (i as u8).wrapping_add(0x31)),
                    std::array::from_fn(|i| (i as u8).wrapping_add(0x91)),
                ],
                constant_pok_commitment: std::array::from_fn(|i| (i as u8).wrapping_add(0x51)),
                constant_pok_response: hash(0x71),
            };
            let mut decode_dealer = |bytes: &[u8]| {
                let result = {
                    let mut ledger = Ledger::new(&pool).unwrap();
                    let mut destination = Dealer::new(&pool, &mut ledger);
                    TleAdaptiveDealerCommitmentV1::decode_fields(bytes, &mut destination).map(
                        |(_, used)| {
                            let decoded = destination.finish().unwrap();
                            assert_eq!(decoded, dealer);
                            assert_eq!(
                                decoded.coefficient_commitments,
                                dealer.coefficient_commitments
                            );
                            drop(decoded);
                            used
                        },
                    )
                };
                assert_eq!(pool.reserved_bytes(), 0);
                result
            };
            check_raw_record::<96, _>(&dealer, &[2], 0, false, &mut decode_dealer);
            check_raw_record::<32, _>(&dealer, &[3], 0, false, &mut decode_dealer);
            let share = TleAdaptivePublicShareV1 {
                index: 3,
                participant_hash: hash(0x81),
                public_key_share: std::array::from_fn(|i| (i as u8).wrapping_add(0xa1)),
            };
            let mut decode_share = |bytes: &[u8]| {
                let result = {
                    let mut ledger = Ledger::new(&pool).unwrap();
                    let mut destination = PublicShare::new(&pool, &mut ledger);
                    TleAdaptivePublicShareV1::decode_fields(bytes, &mut destination).map(
                        |(_, used)| {
                            assert_eq!(destination.finish().unwrap(), share);
                            used
                        },
                    )
                };
                assert_eq!(pool.reserved_bytes(), 0);
                result
            };
            check_raw_record::<32, _>(&share, &[1], 0, true, &mut decode_share);
            check_raw_record::<96, _>(&share, &[2], 0, true, &mut decode_share);
        }
    }
}
