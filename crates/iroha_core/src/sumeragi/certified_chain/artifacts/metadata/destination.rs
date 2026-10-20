//! One canonical field traversal into prepaid metadata, or an allocation-free reject probe.

use super::*;
use ncore::{DecodeIntoError, FieldDestination, PreparedRecordDestination, SerializePayload};

// Payload fields precede every backing/charge owner in destruction order. Reset
// changes validity only; one-shot attempts retain initialized prefix storage until
// the entire destination is discarded after a codec, local failure or unwind.
struct HeaderBacking<'a> {
    keys: Option<ChargedBuffer<PublicKey>>,
    ledger: ChargedBuffer<AllocationCharge>,
    reservation: &'a mut AllocationReservation,
}
struct HeaderDestination<'a> {
    value: BlockHeader,
    backing: Option<HeaderBacking<'a>>,
    valid: bool,
}
struct QcDestination<'a> {
    value: Qc,
    ledger: Option<ChargedBuffer<AllocationCharge>>,
    reservation: Option<&'a mut AllocationReservation>,
    valid: bool,
}
fn blank_header() -> BlockHeader {
    BlockHeader {
        instance: Hash32([0; 32]),
        epoch: EpochId {
            epoch: 0,
            context: Hash32([0; 32]),
        },
        height: 0,
        origin_view: 0,
        parent_hash: Hash32([0; 32]),
        parent_result: Hash32([0; 32]),
        payload_hash: Hash32([0; 32]),
        availability_digest: Hash32([0; 32]),
        payload_len: 0,
        proposer: 0,
        skipped_leaders: Vec::new(),
        control_witness: ControlWitness::empty(),
    }
}
fn blank_qc() -> Qc {
    Qc {
        kind: VoteKind::Commit,
        instance: Hash32([0; 32]),
        epoch: EpochId {
            epoch: 0,
            context: Hash32([0; 32]),
        },
        height: 0,
        view: 0,
        block_hash: Hash32([0; 32]),
        result: Hash32([0; 32]),
        signers: Bitmap::from_bytes(Vec::new()),
        agg_sig: AggregateSignature([0; iroha_sumeragi::types::SIGNATURE_LEN]),
    }
}
impl FieldDestination for HeaderDestination<'_> {
    type Error = CertificateReadError;
}
impl FieldDestination for QcDestination<'_> {
    type Error = CertificateReadError;
}
macro_rules! leaf {
    ($destination:ident, $index:literal, $ty:ty, $member:ident) => {
        impl ncore::DecodeField<$index, $ty> for $destination<'_> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: ncore::CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Self::Error>> {
                self.value.$member = field.with_payload(|bytes| {
                    <$ty as InlineLeaf>::decode(bytes).map_err(DecodeIntoError::Codec)
                })?;
                Ok(())
            }
        }
    };
}
leaf!(HeaderDestination, 0, Hash32, instance);
leaf!(HeaderDestination, 1, EpochId, epoch);
leaf!(HeaderDestination, 2, u64, height);
leaf!(HeaderDestination, 3, u64, origin_view);
leaf!(HeaderDestination, 4, Hash32, parent_hash);
leaf!(HeaderDestination, 5, Hash32, parent_result);
leaf!(HeaderDestination, 6, Hash32, payload_hash);
leaf!(HeaderDestination, 7, Hash32, availability_digest);
leaf!(HeaderDestination, 8, u32, payload_len);
leaf!(HeaderDestination, 9, u32, proposer);
leaf!(QcDestination, 0, VoteKind, kind);
leaf!(QcDestination, 1, Hash32, instance);
leaf!(QcDestination, 2, EpochId, epoch);
leaf!(QcDestination, 3, u64, height);
leaf!(QcDestination, 4, u64, view);
leaf!(QcDestination, 5, Hash32, block_hash);
leaf!(QcDestination, 6, Hash32, result);

impl ncore::DecodeField<10, Vec<PublicKey>> for HeaderDestination<'_> {
    type Value = ();
    #[allow(
        unsafe_code,
        reason = "move unchanged prepaid key Vec allocations into canonical fields while retaining every charge"
    )]
    fn decode_field(
        &mut self,
        field: ncore::CanonicalField<'_, Vec<PublicKey>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            // The shared sequence kernel preserves ordinary count/span/element
            // accounting and late framing precedence. Scratch is finite inline storage.
            let mut spans = [ncore::SequenceSpan { start: 0, end: 0 }; MAX_COMMITTEE_SIZE];
            let plan =
                ncore::prepare_element_sequence(bytes, &mut spans).map_err(
                    |error| match error {
                        ncore::SequenceDestinationError::Codec(error) => {
                            DecodeIntoError::Codec(error)
                        }
                        ncore::SequenceDestinationError::Storage { .. } => {
                            DecodeIntoError::Codec(norito::Error::NonCanonicalEncoding)
                        }
                    },
                )?;
            plan.decode_elements::<PublicKey, CertificateReadError>(|index, field| {
                field.with_payload(|bytes| {
                    with_wrapped_bytes(bytes, 1, MAX_PUBLIC_KEY_LEN, |bytes| {
                        if let Some(backing) = &mut self.backing {
                            let bytes = key_backing(index, bytes, backing.reservation)
                                .map_err(DecodeIntoError::Destination)?;
                            // SAFETY: PublicKey::new consumes this exact Vec without growth.
                            // The ledger precedes every subsequent fallible operation.
                            let (bytes, charge) = unsafe { bytes.into_allocation_parts() };
                            backing.ledger.push_reserved(charge);
                            let key = PublicKey::new(bytes)
                                .map_err(|_| norito::Error::NonCanonicalEncoding)?;
                            backing
                                .keys
                                .as_mut()
                                .expect("unmoved original key array")
                                .push_reserved(key);
                            #[cfg(test)]
                            checkpoint(index);
                        }
                        Ok(())
                    })
                })
            })?;
            if plan.used() != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            if let Some(backing) = &mut self.backing {
                // SAFETY: the unchanged array and its key byte allocations immediately
                // become fields of the payload whose ledger is retained beside it.
                let (keys, charge) = unsafe {
                    backing
                        .keys
                        .take()
                        .expect("original key array")
                        .into_allocation_parts()
                };
                backing.ledger.push_reserved(charge);
                self.value.skipped_leaders = keys;
            }
            Ok(())
        })
    }
}
impl ncore::DecodeField<11, ControlWitness> for HeaderDestination<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: ncore::CanonicalField<'_, ControlWitness>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        self.value.control_witness = field
            .with_payload(|bytes| ControlWitness::decode(bytes).map_err(DecodeIntoError::Codec))?;
        self.valid = self.backing.is_some();
        Ok(())
    }
}
impl ncore::DecodeField<7, Bitmap> for QcDestination<'_> {
    type Value = ();
    #[allow(
        unsafe_code,
        reason = "canonical bitmap consumes exact prepaid Vec and retains its original charge"
    )]
    fn decode_field(
        &mut self,
        field: ncore::CanonicalField<'_, Bitmap>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            with_wrapped_bytes(bytes, 0, MAX_BITMAP_BYTES, |bytes| {
                if let Some(reservation) = &mut self.reservation {
                    let bytes =
                        byte_backing(bytes, reservation).map_err(DecodeIntoError::Destination)?;
                    // SAFETY: the unchanged original Vec and ledger enter the same payload.
                    let (bytes, charge) = unsafe { bytes.into_allocation_parts() };
                    self.ledger
                        .as_mut()
                        .expect("original bitmap ledger")
                        .push_reserved(charge);
                    self.value.signers = Bitmap::from_bytes(bytes);
                }
                Ok(())
            })
        })
    }
}
impl ncore::DecodeField<8, AggregateSignature> for QcDestination<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: ncore::CanonicalField<'_, AggregateSignature>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        self.value.agg_sig = field.with_payload(|bytes| {
            AggregateSignature::decode(bytes).map_err(DecodeIntoError::Codec)
        })?;
        self.valid = self.ledger.is_some();
        Ok(())
    }
}
macro_rules! record {
    ($destination:ident, $value:ty) => {
        impl SerializePayload for $destination<'_> {
            fn serialize(&self, encoder: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
                if !self.valid {
                    return Err(norito::Error::LengthMismatch);
                }
                SerializePayload::serialize(&self.value, encoder)
            }
        }
        impl PreparedRecordDestination<$value> for $destination<'_> {
            fn reset(&mut self) {
                self.valid = false;
            }
        }
    };
}
record!(HeaderDestination, BlockHeader);
record!(QcDestination, Qc);

fn fill<T, D>(
    work: &mut ncore::PreparedDecodeWorkspace,
    raw: &[u8],
    destination: &mut D,
) -> Result<(), CertificateReadError>
where
    T: ncore::NoritoSerialize + ncore::DecodeRecordFields<D>,
    for<'de> T: ncore::NoritoDeserialize<'de> + ncore::DecodeFromSlice<'de>,
    D: PreparedRecordDestination<T, Error = CertificateReadError>,
{
    #[cfg(all(test, sumeragi_core_mutation = "HC968"))]
    let result = work.decode_canonical_archive_into::<T, D>(
        raw,
        norito::canonical_decode_limits(raw.len()),
        destination,
    );
    #[cfg(not(all(test, sumeragi_core_mutation = "HC968")))]
    let result = work.decode_canonical_into::<T, D>(
        raw,
        norito::canonical_decode_limits(raw.len()),
        destination,
    );
    result.map_err(prepared_error)
}

#[allow(
    unsafe_code,
    reason = "the final payload owns every unchanged prepaid allocation and its complete original ledger"
)]
pub(super) fn header(
    raw: &[u8],
    plan: Option<HeaderPlan>,
    budget: &AllocationBudget,
) -> Result<FundedMetadata<BlockHeader>, CertificateReadError> {
    let plan = match plan {
        Some(plan) => plan,
        None => {
            let mut reservation = budget
                .try_reserve_bytes(workspace_bytes()?)
                .map_err(admission)?;
            let mut work = workspace(budget, &mut reservation)?;
            let mut probe = HeaderDestination {
                value: blank_header(),
                backing: None,
                valid: false,
            };
            // No payload allocation or second decode: actual root/field errors win.
            fill::<BlockHeader, _>(&mut work, raw, &mut probe)?;
            return Err(CertificateReadError::Decode(norito::Error::LengthMismatch));
        }
    };
    let mut reservation = budget
        .try_reserve_bytes(demand::<BlockHeader>(plan.count + 1, plan.backing)?)
        .map_err(admission)?;
    let mut work = workspace(budget, &mut reservation)?;
    let shell = ChargedShared::<RetainedPayload<BlockHeader>>::reserve_from(&mut reservation)
        .map_err(|error| {
            CertificateReadError::Admission(ByteAdmissionError::ControlAllocation(error))
        })?;
    let ledger =
        ChargedBuffer::from_reservation(plan.count + 1, &mut reservation).map_err(prepaid)?;
    let keys = ChargedBuffer::from_reservation(plan.count, &mut reservation).map_err(prepaid)?;
    let mut destination = HeaderDestination {
        value: blank_header(),
        backing: Some(HeaderBacking {
            keys: Some(keys),
            ledger,
            reservation: &mut reservation,
        }),
        valid: false,
    };
    fill::<BlockHeader, _>(&mut work, raw, &mut destination)?;
    let HeaderDestination { value, backing, .. } = destination;
    let ledger = backing.expect("completed funded destination").ledger;
    // SAFETY: value has precisely the original prepaid array/key allocations.
    let retained = match unsafe { RetainedPayload::try_new(value, ledger, budget) } {
        Ok(value) => value,
        Err((value, ledger, _)) => {
            drop(value);
            drop(ledger);
            return Err(CertificateReadError::ForeignBudget);
        }
    };
    debug_assert_eq!(reservation.remaining_bytes(), 0);
    Ok(FundedMetadata(shell.initialize(retained)))
}

#[allow(
    unsafe_code,
    reason = "the final payload owns the unchanged prepaid bitmap and its complete original ledger"
)]
pub(super) fn qc(
    raw: &[u8],
    plan: Option<QcPlan>,
    budget: &AllocationBudget,
) -> Result<FundedMetadata<Qc>, CertificateReadError> {
    let plan = match plan {
        Some(plan) => plan,
        None => {
            let mut reservation = budget
                .try_reserve_bytes(workspace_bytes()?)
                .map_err(admission)?;
            let mut work = workspace(budget, &mut reservation)?;
            let mut probe = QcDestination {
                value: blank_qc(),
                ledger: None,
                reservation: None,
                valid: false,
            };
            fill::<Qc, _>(&mut work, raw, &mut probe)?;
            return Err(CertificateReadError::Decode(norito::Error::LengthMismatch));
        }
    };
    let mut reservation = budget
        .try_reserve_bytes(demand::<Qc>(1, plan.backing)?)
        .map_err(admission)?;
    let mut work = workspace(budget, &mut reservation)?;
    let shell =
        ChargedShared::<RetainedPayload<Qc>>::reserve_from(&mut reservation).map_err(|error| {
            CertificateReadError::Admission(ByteAdmissionError::ControlAllocation(error))
        })?;
    let ledger = ChargedBuffer::from_reservation(1, &mut reservation).map_err(prepaid)?;
    let mut destination = QcDestination {
        value: blank_qc(),
        ledger: Some(ledger),
        reservation: Some(&mut reservation),
        valid: false,
    };
    fill::<Qc, _>(&mut work, raw, &mut destination)?;
    let QcDestination { value, ledger, .. } = destination;
    // SAFETY: value owns exactly the prepaid bitmap recorded in this original ledger.
    let retained = match unsafe {
        RetainedPayload::try_new(value, ledger.expect("completed bitmap ledger"), budget)
    } {
        Ok(value) => value,
        Err((value, ledger, _)) => {
            drop(value);
            drop(ledger);
            return Err(CertificateReadError::ForeignBudget);
        }
    };
    debug_assert_eq!(reservation.remaining_bytes(), 0);
    Ok(FundedMetadata(shell.initialize(retained)))
}
