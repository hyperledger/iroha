//! Exact physical custody for the closed native pin/control transaction graph.
//!
//! This copies already selected canonical values; it neither signs nor admits a transaction.
//! Every destination layout is prepaid from one pool and survives with the immutable graph.
//! The ordinary source, cryptographic validation, encoder output and Queue metadata are separate
//! owners. In particular, a borrowed graph's ordinary Clone is not funded by this owner.

use std::{alloc::Layout, fmt};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferError, PrepaidBufferError, RetainedPayload,
};
use iroha_crypto::{Algorithm, SignatureOf};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::{bigint::BigIntAdmissionCloneError, const_vec::ConstVec};

use super::{
    AuthorityFeePayment, FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction,
    TransactionDomain, TransactionEntrypoint, TransactionPayload, TransactionSignature,
};
use crate::{
    account::AccountId,
    isi::{
        Instruction as _, InstructionBox,
        musubi::{AdvanceMusubiPinOutboxV1, CheckMusubiPinOutboxV1},
        sorafs::RegisterPinManifest,
    },
    musubi::{MusubiPinOutboxCheckExpectationV1, MusubiPinOutboxHighWaterV1},
    transaction::Executable,
};

const MAX_FEES: usize = 16;
const MAX_FRAME: usize = 128 * 1024;

/// Local physical or canonical-resource refusal while copying a closed native pin graph.
#[derive(Debug, thiserror::Error)]
pub enum PinTransactionAllocationErrorV1 {
    /// The selected envelope is outside this narrowly owned native instruction profile.
    #[error("unsupported native pin transaction allocation profile")]
    Profile,
    /// Original finite pool admission failed before allocating the destination graph.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Canonical measurement or inherited cumulative allowance refused the original request.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// A physically prepaid destination allocation failed.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// The exact existing numeric mantissa could not be copied.
    #[error(transparent)]
    Quantity(#[from] BigIntAdmissionCloneError),
}
use PinTransactionAllocationErrorV1 as Error;

/// Move-only exact canonical External input and every original nested allocation charge.
///
/// The private constructor copies only the three native pin/outbox instructions, a direct
/// Ed25519 authority, bounded authority-paid Nexus limits, and an otherwise empty native
/// envelope. This is allocation custody, never permission, signature validation or finality.
pub struct AllocatedPinTransactionV1(RetainedPayload<TransactionEntrypoint>);
impl fmt::Debug for AllocatedPinTransactionV1 {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("AllocatedPinTransactionV1")
            .finish_non_exhaustive()
    }
}
impl AllocatedPinTransactionV1 {
    /// Copy the exact selected source with physically prepaid backing for every nested field.
    ///
    /// This never invokes SignedTransaction/InstructionBox Clone, re-signs, decodes, normalizes
    /// amounts or changes nonce/time/fees. The source remains unchanged on every refusal.
    /// # Errors
    /// Refuses unsupported graph shape, bounds, inherited quota, pool capacity or allocation.
    pub fn copy_from(signed: &SignedTransaction, budget: &AllocationBudget) -> Result<Self, Error> {
        let source = Source::new(signed)?;
        let demand = source.demand()?;
        // One reservation owns all real layouts including the ledger, before the first copy.
        let mut reservation = budget.try_reserve_bytes(demand.bytes)?;
        let mut ledger = Ledger::new(budget, &mut reservation, demand.count)?;
        // Ledger is declared before all produced values. Partial fields and any completed graph
        // are destroyed before its charges on every normal error and unwinding path.
        let authority = ledger.account(&signed.payload.authority)?;
        let instruction = source.action.copy(&mut ledger)?;
        let mut instructions = ledger.buffer::<InstructionBox>(1)?;
        instructions.push_reserved(instruction);
        let instructions = ledger.take(instructions).into_boxed_slice();
        let mut fees = ledger.buffer::<FeeChargeLimit>(source.fees.charge_limits.len())?;
        for fee in &source.fees.charge_limits {
            let layout = fee.max_amount.admission_clone_layout()?;
            ledger.prepay_detached(layout)?;
            let amount = fee.max_amount.try_clone_for_admission()?;
            fees.push_reserved(FeeChargeLimit {
                kind: fee.kind,
                // AssetDefinitionId is the inline 16-byte canonical UUID, with no heap fields.
                asset_definition_id: fee.asset_definition_id.clone(),
                max_amount: amount,
            });
        }
        let fee_payment = FeePaymentIntent::Authority(AuthorityFeePayment {
            charge_limits: ledger.take(fees),
            gas_limit: None,
        });
        let signature = ledger.signature(&signed.signature.0)?;
        let exact = TransactionEntrypoint::External(SignedTransaction {
            signature: TransactionSignature(SignatureOf::from_signature(signature)),
            payload: TransactionPayload {
                domain: signed.payload.domain,
                authority,
                creation_time_ms: signed.payload.creation_time_ms,
                instructions: Executable::Instructions(ConstVec::new(instructions)),
                time_to_live_ms: signed.payload.time_to_live_ms,
                nonce: signed.payload.nonce,
                fee_payment,
                metadata: Metadata::default(),
                attachments: None,
            },
            multisig_signatures: None,
            entrypoint_hash: Default::default(),
        });
        let (charges, complete) = ledger.finish();
        if !complete {
            drop(exact);
            drop(charges);
            return Err(Error::Profile);
        }
        // SAFETY: Source/demand enumerate every allocation of this closed profile. All field
        // producers below allocate exactly those layouts; vectors never grow and exact-capacity
        // Box conversions cannot reallocate. The complete graph has no mutable/shared escape.
        // RetainedPayload destroys all fields before the immutable ledger, including unwind.
        #[allow(unsafe_code)]
        let retained = match unsafe { RetainedPayload::try_new(exact, charges, budget) } {
            Ok(retained) => retained,
            Err((exact, charges, _)) => {
                // Even an internal pool-identity inconsistency cannot refund backing before
                // destroying the graph that owns it.
                drop(exact);
                drop(charges);
                return Err(Error::Profile);
            }
        };
        Ok(Self(retained))
    }

    /// Borrow the complete original canonical External input without separating its custody.
    pub fn entrypoint(&self) -> &TransactionEntrypoint {
        self.0.get()
    }
    /// Borrow the exact signed transaction; this grants no signature or admission authority.
    pub fn signed(&self) -> &SignedTransaction {
        let TransactionEntrypoint::External(signed) = self.entrypoint() else {
            unreachable!("private constructor only creates External inputs")
        };
        signed
    }
    /// Confirm exact original allocation pool identity, not merely equal capacity limits.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget)
    }
    /// Actual retained nested allocations and their ledger backing, excluding caller controls.
    pub fn allocation_bytes(&self) -> Option<usize> {
        self.0.allocation_bytes()
    }
}

struct Source<'a> {
    signed: &'a SignedTransaction,
    action: Action<'a>,
    fees: &'a AuthorityFeePayment,
}
impl<'a> Source<'a> {
    fn new(signed: &'a SignedTransaction) -> Result<Self, Error> {
        let p = signed.payload();
        if !matches!(p.domain, TransactionDomain::Network(_))
            || p.time_to_live_ms.is_none()
            || p.creation_time_ms == 0
            || !p.metadata.is_empty()
            || p.attachments.is_some()
            || signed.multisig_signatures().is_some()
            || signed.signature().0.payload().len() != 64
        {
            return Err(Error::Profile);
        }
        direct_key(&p.authority)?;
        let FeePaymentIntent::Authority(fees) = &p.fee_payment else {
            return Err(Error::Profile);
        };
        if fees.gas_limit.is_some()
            || fees.charge_limits.len() > MAX_FEES
            || fees
                .charge_limits
                .iter()
                .any(|fee| fee.kind != FeeChargeKind::Nexus)
        {
            return Err(Error::Profile);
        }
        let Executable::Instructions(instructions) = &p.instructions else {
            return Err(Error::Profile);
        };
        if instructions.len() != 1 {
            return Err(Error::Profile);
        }
        if signed.wire_plan_v1()?.wire_length() > MAX_FRAME {
            return Err(Error::Profile);
        }
        Ok(Self {
            signed,
            action: Action::select(&instructions[0])?,
            fees,
        })
    }
    fn demand(&self) -> Result<Demand, Error> {
        let mut d = Demand::default();
        d.account(&self.signed.payload.authority)?;
        self.action.demand(&mut d)?;
        d.add(Layout::array::<InstructionBox>(1).map_err(|_| Error::Profile)?)?;
        d.add(
            Layout::array::<FeeChargeLimit>(self.fees.charge_limits.len())
                .map_err(|_| Error::Profile)?,
        )?;
        for fee in &self.fees.charge_limits {
            d.add(fee.max_amount.admission_clone_layout()?)?;
        }
        d.add(self.signed.signature.0.retained_allocation_layout())?;
        let ledger = Layout::array::<AllocationCharge>(d.count).map_err(|_| Error::Profile)?;
        d.bytes = d.bytes.checked_add(ledger.size()).ok_or(Error::Profile)?;
        Ok(d)
    }
}
fn direct_key(account: &AccountId) -> Result<&iroha_crypto::PublicKey, Error> {
    let key = account.try_signatory().ok_or(Error::Profile)?;
    if key.try_algorithm().map_err(|_| Error::Profile)? != Algorithm::Ed25519 {
        return Err(Error::Profile);
    }
    Ok(key)
}
#[derive(Default)]
struct Demand {
    bytes: usize,
    count: usize,
}
impl Demand {
    fn add(&mut self, layout: Layout) -> Result<(), Error> {
        self.bytes = self
            .bytes
            .checked_add(layout.size())
            .ok_or(Error::Profile)?;
        self.count = self.count.checked_add(1).ok_or(Error::Profile)?;
        Ok(())
    }
    fn account(&mut self, value: &AccountId) -> Result<(), Error> {
        self.add(direct_key(value)?.retained_allocation_layout())
    }
}

enum Action<'a> {
    Pin(&'a RegisterPinManifest),
    Advance(&'a AdvanceMusubiPinOutboxV1),
    Check(&'a CheckMusubiPinOutboxV1),
}
impl<'a> Action<'a> {
    fn select(value: &'a InstructionBox) -> Result<Self, Error> {
        if let Some(pin) = value.as_any().downcast_ref::<RegisterPinManifest>() {
            if pin.alias.is_some() || pin.successor_of.is_some() {
                return Err(Error::Profile);
            }
            return Ok(Self::Pin(pin));
        }
        if let Some(value) = value.as_any().downcast_ref::<AdvanceMusubiPinOutboxV1>() {
            return Ok(Self::Advance(value));
        }
        if let Some(value) = value.as_any().downcast_ref::<CheckMusubiPinOutboxV1>() {
            return Ok(Self::Check(value));
        }
        Err(Error::Profile)
    }
    fn demand(&self, d: &mut Demand) -> Result<(), Error> {
        match self {
            Self::Pin(v) => {
                d.add(Layout::array::<u8>(v.manifest_payload.len()).map_err(|_| Error::Profile)?)?;
                d.add(Layout::new::<RegisterPinManifest>())?;
            }
            Self::Advance(v) => {
                d.account(&v.pin_authority)?;
                d.add(Layout::new::<AdvanceMusubiPinOutboxV1>())?;
            }
            Self::Check(v) => {
                d.account(&v.pin_authority)?;
                if let MusubiPinOutboxCheckExpectationV1::Present(row) = &v.expected {
                    d.account(&row.pin_authority)?;
                }
                d.add(Layout::new::<CheckMusubiPinOutboxV1>())?;
            }
        }
        Ok(())
    }
    fn copy(&self, l: &mut Ledger<'_>) -> Result<InstructionBox, Error> {
        match self {
            Self::Pin(v) => {
                let mut bytes = l.buffer(v.manifest_payload.len())?;
                bytes
                    .append(&v.manifest_payload)
                    .expect("exact selected capacity");
                let pin = RegisterPinManifest {
                    manifest_payload: l.take(bytes),
                    alias: None,
                    successor_of: None,
                };
                Ok(l.boxed(pin)?.into_instruction_box())
            }
            Self::Advance(v) => {
                let value = AdvanceMusubiPinOutboxV1 {
                    network_id: v.network_id,
                    pin_authority: l.account(&v.pin_authority)?,
                    session_id: v.session_id,
                    expected_revision: v.expected_revision,
                    expected_inventory_digest: v.expected_inventory_digest,
                    inventory_digest: v.inventory_digest,
                };
                Ok(l.boxed(value)?.into_instruction_box())
            }
            Self::Check(v) => {
                let authority = l.account(&v.pin_authority)?;
                let expected = match &v.expected {
                    MusubiPinOutboxCheckExpectationV1::Absent => {
                        MusubiPinOutboxCheckExpectationV1::Absent
                    }
                    MusubiPinOutboxCheckExpectationV1::Present(r) => {
                        MusubiPinOutboxCheckExpectationV1::Present(MusubiPinOutboxHighWaterV1 {
                            version: r.version,
                            network_id: r.network_id,
                            pin_authority: l.account(&r.pin_authority)?,
                            session_id: r.session_id,
                            revision: r.revision,
                            inventory_digest: r.inventory_digest,
                            recorded_at_height: r.recorded_at_height,
                            transaction_hash: r.transaction_hash,
                        })
                    }
                };
                let value = CheckMusubiPinOutboxV1 {
                    network_id: v.network_id,
                    pin_authority: authority,
                    session_id: v.session_id,
                    inventory_digest: v.inventory_digest,
                    challenge: v.challenge,
                    floor: v.floor,
                    expected,
                };
                Ok(l.boxed(value)?.into_instruction_box())
            }
        }
    }
}

struct Ledger<'a> {
    budget: &'a AllocationBudget,
    reservation: &'a mut AllocationReservation,
    charges: ChargedBuffer<AllocationCharge>,
}
impl<'a> Ledger<'a> {
    fn new(
        budget: &'a AllocationBudget,
        reservation: &'a mut AllocationReservation,
        count: usize,
    ) -> Result<Self, Error> {
        norito::core::reserve_decode_allocation(
            Layout::array::<AllocationCharge>(count)
                .map_err(|_| Error::Profile)?
                .size(),
        )?;
        let charges = ChargedBuffer::from_reservation(count, reservation).map_err(prepaid_error)?;
        Ok(Self {
            budget,
            reservation,
            charges,
        })
    }
    fn buffer<T>(&mut self, count: usize) -> Result<ChargedBuffer<T>, Error> {
        let layout = Layout::array::<T>(count).map_err(|_| Error::Profile)?;
        norito::core::reserve_decode_allocation(layout.size())?;
        ChargedBuffer::from_reservation(count, self.reservation).map_err(prepaid_error)
    }
    fn take<T>(&mut self, buffer: ChargedBuffer<T>) -> Vec<T> {
        // SAFETY: all callers immediately move this fixed backing into a local field of the
        // final canonical graph; no mutation/growth or extraction follows. The ledger is declared
        // before every such field and owns its charge until RetainedPayload takes over.
        #[allow(unsafe_code)]
        let (values, charge) = unsafe { buffer.into_allocation_parts() };
        self.charges.push_reserved(charge);
        values
    }
    fn account(&mut self, account: &AccountId) -> Result<AccountId, Error> {
        let key = direct_key(account)?;
        let layout = key.retained_allocation_layout();
        norito::core::reserve_decode_allocation(layout.size())?;
        let charge = self
            .reservation
            .try_split(layout)
            .map_err(|_| Error::Profile)?;
        let key =
            key.try_clone_from_charge(self.budget, charge)
                .map_err(|(_, error)| match error {
                    iroha_crypto::PublicKeyAllocationError::Allocation(
                        iroha_allocation::ChargedBufferFromChargeError::Allocator { layout },
                    ) => Error::Allocation(ChargedBufferError::Allocator {
                        requested_bytes: layout.size(),
                    }),
                    _ => Error::Profile,
                })?;
        // SAFETY: immediately retain the exact key charge in this ledger and move its immutable
        // compact Box into the canonical account. Source profile excludes multisig graphs.
        #[allow(unsafe_code)]
        let (key, charge) = unsafe { key.into_allocation_parts() };
        self.charges.push_reserved(charge);
        Ok(AccountId::new(key))
    }
    fn signature(
        &mut self,
        signature: &iroha_crypto::Signature,
    ) -> Result<iroha_crypto::Signature, Error> {
        let layout = signature.retained_allocation_layout();
        norito::core::reserve_decode_allocation(layout.size())?;
        let charge = self
            .reservation
            .try_split(layout)
            .map_err(|_| Error::Profile)?;
        let copied = signature
            .try_clone_from_charge(self.budget, charge)
            .map_err(|(_, error)| match error {
                iroha_crypto::SignatureAllocationError::Allocation(
                    iroha_allocation::ChargedBufferFromChargeError::Allocator { layout },
                ) => Error::Allocation(ChargedBufferError::Allocator {
                    requested_bytes: layout.size(),
                }),
                _ => Error::Profile,
            })?;
        // SAFETY: exact immutable signature payload and charge move together into the same
        // audited graph/ledger; there is no intermediate fallible work or allocation.
        #[allow(unsafe_code)]
        let (signature, charge) = unsafe { copied.into_allocation_parts() };
        self.charges.push_reserved(charge);
        Ok(signature)
    }
    fn prepay_detached(&mut self, layout: Layout) -> Result<(), Error> {
        norito::core::reserve_decode_allocation(layout.size())?;
        let charge = self
            .reservation
            .try_split(layout)
            .map_err(|_| Error::Profile)?;
        self.charges.push_reserved(charge);
        Ok(())
    }
    fn boxed<T>(&mut self, value: T) -> Result<Box<T>, Error> {
        let mut buffer = self.buffer(1)?;
        buffer.push_reserved(value);
        let slice = self.take(buffer).into_boxed_slice();
        // SAFETY: one initialized T, exact Layout::array::<T>(1)==Layout::new::<T>(). The
        // canonical Box owns that same global allocation; no allocator call or growth occurs.
        #[allow(unsafe_code)]
        Ok(unsafe { Box::from_raw(Box::into_raw(slice).cast::<T>()) })
    }
    fn finish(self) -> (ChargedBuffer<AllocationCharge>, bool) {
        // No refusal may drop this ledger while the completed payload remains in the caller.
        // First bind both into RetainedPayload, then inspect this fixed accounting invariant.
        let complete = self.charges.as_slice().len() == self.charges.capacity()
            && self.reservation.remaining_bytes() == 0;
        (self.charges, complete)
    }
}
fn prepaid_error(error: PrepaidBufferError) -> Error {
    match error {
        PrepaidBufferError::Allocation(error) => Error::Allocation(error),
        // The complete geometry was admitted before copying. A shortage is an internal profile
        // disagreement, never a retry with a silently enlarged budget.
        PrepaidBufferError::Reservation(_) => Error::Profile,
    }
}

#[cfg(test)]
#[path = "pin_allocation/tests.rs"]
mod tests;
