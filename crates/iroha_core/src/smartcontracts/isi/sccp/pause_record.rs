//! Immutable original-pool custody of SCCP pause, panel and endorsement State graphs.
//!
//! Ordinary MV versions clone only the charged shared owner. Snapshot DTOs and new effects
//! require exact admission of every backing, nested AccountId allocation, ledger and shell.
//! No BTreeMap/BTreeSet node is created for these payloads: canonical ordered buffers project
//! the same wire layout. The enclosing State map/cell owners retain their existing accounting.

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferError, ChargedShared, PrepaidBufferError, PrepaidSharedError, RetainedPayload,
};
use iroha_data_model::{
    account::AccountId,
    sccp::fast_pause::{
        SccpFastPauseEndorsementV1, SccpFastPauseRoundV1, SccpFastPauseV1, SccpPausePanelV1,
    },
};
use norito::{
    core::{Encoder, SerializePayload},
    json::{self, JsonSerialize},
};
use std::{alloc::Layout, fmt, ops::Deref};

mod draft;
pub(crate) use draft::{FastPauseDraft, FastPauseRoundDraft, PausePanelDraft};

/// Structural rejection stays distinct from original local allocation refusal.
#[derive(Debug, thiserror::Error)]
pub enum PauseRecordError {
    /// Invalid canonical record or construction relation.
    #[error("invalid SCCP pause graph: {0}")]
    Invalid(&'static str),
    /// Original configured execution pool refused admission.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// The physical allocator refused an already admitted allocation.
    #[error("SCCP pause graph allocation unavailable ({bytes} bytes)")]
    Allocator {
        /// Exact requested size.
        bytes: usize,
    },
    /// Canonical account cloning failed; logical resource failures remain identifiable.
    #[error(transparent)]
    Account(#[from] norito::core::Error),
}

#[derive(Default)]
struct Demand {
    bytes: usize,
    charges: usize,
}
impl Demand {
    fn total_bytes<T>(&self) -> Result<usize, PauseRecordError> {
        let ledger = Layout::array::<AllocationCharge>(self.charges)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        let shell = ChargedShared::<RetainedPayload<T>>::allocation_layout();
        self.bytes
            .checked_add(ledger.size())
            .and_then(|n| n.checked_add(shell.size()))
            .ok_or_else(|| AllocationRefusal::DemandOverflow.into())
    }
    fn add(&mut self, layout: Layout) -> Result<(), PauseRecordError> {
        self.bytes = self
            .bytes
            .checked_add(layout.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        self.charges = self
            .charges
            .checked_add(1)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(())
    }
    fn array<T>(&mut self, n: usize) -> Result<(), PauseRecordError> {
        self.add(Layout::array::<T>(n).map_err(|_| AllocationRefusal::DemandOverflow)?)
    }
}
fn prepaid_error(error: PrepaidBufferError) -> PauseRecordError {
    match error {
        PrepaidBufferError::Allocation(ChargedBufferError::Allocator { requested_bytes }) => {
            PauseRecordError::Allocator {
                bytes: requested_bytes,
            }
        }
        PrepaidBufferError::Allocation(ChargedBufferError::Admission(original)) => original.into(),
        PrepaidBufferError::Reservation(_) => {
            PauseRecordError::Invalid("original reservation mismatch")
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConstructionCheckpoint {
    NestedAccount,
    BeforeSharedShell,
}
#[cfg(test)]
thread_local! {
    static CONSTRUCTION_UNWIND: std::cell::Cell<Option<ConstructionCheckpoint>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn construction_checkpoint(stage: ConstructionCheckpoint) {
    if CONSTRUCTION_UNWIND.with(|requested| requested.get() == Some(stage)) {
        CONSTRUCTION_UNWIND.with(|requested| requested.set(None));
        panic!("controlled partial construction unwind at {stage:?}");
    }
}

// The partial canonical body drops before its original allocation ledger, including
// when a later physical allocation, validation or caller unwinds. No blanket leak is
// necessary: all partially constructed owned fields remain inside this one owner.
struct Construction<'a, T> {
    body: T,
    charges: ChargedBuffer<AllocationCharge>,
    budget: &'a AllocationBudget,
    reservation: AllocationReservation,
}
impl<'a, T> Construction<'a, T> {
    /// Move the complete private graph directly into its immutable ledger owner.
    /// The checked constructor only compares pool identities: it invokes no user code,
    /// allocation, formatting, assertions or other panic-capable operation between these
    /// field moves and the retained owner. Refusal destroys the body before its ledger.
    #[allow(
        unsafe_code,
        reason = "all body backings were admitted once under the original pool"
    )]
    fn into_payload(self) -> Result<(RetainedPayload<T>, AllocationReservation), PauseRecordError> {
        // SAFETY: every body allocation has its exact charge; no mutable escape exists.
        let payload = unsafe { RetainedPayload::try_new(self.body, self.charges, self.budget) }
            .map_err(|(body, charges, _)| {
                drop(body);
                drop(charges);
                PauseRecordError::Invalid("foreign original pool")
            })?;
        Ok((payload, self.reservation))
    }

    fn new_prepaid(
        demand: Demand,
        budget: &'a AllocationBudget,
        prepaid: &mut AllocationReservation,
        body: T,
    ) -> Result<Self, PauseRecordError> {
        if !prepaid.belongs_to(budget) {
            return Err(PauseRecordError::Invalid("foreign original reservation"));
        }
        let bytes = demand.total_bytes::<T>()?;
        let mut reservation = prepaid
            .try_partition_bytes(bytes)
            .map_err(|_| PauseRecordError::Invalid("incomplete original reservation"))?;
        let charges = ChargedBuffer::from_reservation(demand.charges, &mut reservation)
            .map_err(prepaid_error)?;
        Ok(Self {
            body,
            charges,
            budget,
            reservation,
        })
    }
    fn retain(&mut self, charge: AllocationCharge) -> Result<(), PauseRecordError> {
        if let Err(charge) = self.charges.try_push(charge) {
            // account() reserves before cloning; this charge owns no allocation yet.
            drop(charge);
            return Err(PauseRecordError::Invalid("charge ledger mismatch"));
        }
        Ok(())
    }
    #[allow(
        unsafe_code,
        reason = "exact prepaid backing moves into a private immutable model field"
    )]
    fn vector<U>(&mut self, values: ChargedBuffer<U>) -> Result<Vec<U>, PauseRecordError> {
        // SAFETY: the caller moves this backing into the immutable body and never grows it.
        let (values, charge) = unsafe { values.into_allocation_parts() };
        if let Err(charge) = self.charges.try_push(charge) {
            // Unlike account prepayment, this charge already owns this exact backing.
            drop(values);
            drop(charge);
            return Err(PauseRecordError::Invalid("charge ledger mismatch"));
        }
        Ok(values)
    }
    fn account(&mut self, source: &AccountId) -> Result<AccountId, PauseRecordError> {
        let mut failed = None;
        source.for_each_admission_clone_layout(|layout| {
            if failed.is_some() {
                return;
            }
            match self.reservation.try_split(layout) {
                Ok(charge) => failed = self.retain(charge).err(),
                Err(_) => failed = Some(PauseRecordError::Invalid("account demand changed")),
            }
        })?;
        if let Some(error) = failed {
            return Err(error);
        }
        let account = source.try_clone_for_admission()?;
        #[cfg(test)]
        construction_checkpoint(ConstructionCheckpoint::NestedAccount);
        Ok(account)
    }
    fn accounts<'b>(
        &mut self,
        count: usize,
        source: impl IntoIterator<Item = &'b AccountId> + 'b,
    ) -> Result<Vec<AccountId>, PauseRecordError> {
        let mut buffer =
            ChargedBuffer::from_reservation(count, &mut self.reservation).map_err(prepaid_error)?;
        for account in source {
            buffer
                .try_push(self.account(account)?)
                .map_err(|_| PauseRecordError::Invalid("account count changed"))?;
        }
        if buffer.as_slice().len() != count {
            return Err(PauseRecordError::Invalid("account count changed"));
        }
        self.vector(buffer)
    }
}

fn account_demand(demand: &mut Demand, source: &AccountId) -> Result<(), PauseRecordError> {
    let mut error = None;
    source.for_each_admission_clone_layout(|layout| {
        if error.is_none() {
            error = demand.add(layout).err();
        }
    })?;
    error.map_or(Ok(()), Err)
}

fn publish<T>(
    construction: Construction<'_, T>,
) -> Result<ChargedShared<RetainedPayload<T>>, PauseRecordError> {
    let (payload, mut reservation) = construction.into_payload()?;
    #[cfg(test)]
    construction_checkpoint(ConstructionCheckpoint::BeforeSharedShell);
    let result = ChargedShared::from_reservation(payload, &mut reservation).map_err(
        |(payload, error)| {
            drop(payload);
            match error {
                PrepaidSharedError::Allocator { requested_bytes } => PauseRecordError::Allocator {
                    bytes: requested_bytes,
                },
                PrepaidSharedError::Reservation(_) => {
                    PauseRecordError::Invalid("shared shell reservation")
                }
            }
        },
    )?;
    if reservation.remaining_bytes() != 0 {
        return Err(PauseRecordError::Invalid("unused pause graph demand"));
    }
    Ok(result)
}

/// Original funded current fast-pause record, shared across current/undo readers.
#[derive(Clone)]
pub struct RetainedSccpFastPause(ChargedShared<RetainedPayload<SccpFastPauseV1>>);

impl RetainedSccpFastPause {
    fn demand(source: &SccpFastPauseV1) -> Result<Demand, PauseRecordError> {
        if !source.has_valid_shape() {
            return Err(PauseRecordError::Invalid("fast-pause structure"));
        }
        let mut demand = Demand::default();
        demand.array::<u32>(source.revisions.len())?;
        Ok(demand)
    }
    /// Exact complete graph demand, before any retained owner is constructed.
    pub(crate) fn admission_demand(source: &SccpFastPauseV1) -> Result<usize, PauseRecordError> {
        Self::demand(source)?.total_bytes::<SccpFastPauseV1>()
    }
    /// Admit one structurally valid DTO under the original execution pool.
    #[cfg(test)]
    pub(crate) fn admit(
        source: &SccpFastPauseV1,
        budget: &AllocationBudget,
    ) -> Result<Self, PauseRecordError> {
        let mut reservation = budget.try_reserve_bytes(Self::admission_demand(source)?)?;
        Self::admit_prepaid(source, budget, &mut reservation)
    }
    /// Consume this graph's partition of a complete effect or snapshot reservation.
    pub(crate) fn admit_prepaid(
        source: &SccpFastPauseV1,
        budget: &AllocationBudget,
        prepaid: &mut AllocationReservation,
    ) -> Result<Self, PauseRecordError> {
        let body = SccpFastPauseV1 {
            certificate_id: source.certificate_id,
            effect_hash: source.effect_hash,
            panel_id: source.panel_id,
            enacted_at: source.enacted_at,
            enacted_at_ms: source.enacted_at_ms,
            until_ms: source.until_ms,
            taira: source.taira,
            revisions: Vec::new(),
        };
        let mut construction =
            Construction::new_prepaid(Self::demand(source)?, budget, prepaid, body)?;
        let mut revisions =
            ChargedBuffer::from_reservation(source.revisions.len(), &mut construction.reservation)
                .map_err(prepaid_error)?;
        for value in &source.revisions {
            revisions
                .try_push(*value)
                .map_err(|_| PauseRecordError::Invalid("revision count changed"))?;
        }
        construction.body.revisions = construction.vector(revisions)?;
        Ok(Self(publish(construction)?))
    }
}

/// Immutable ordered buffers of one original panel draw and its accepted members.
#[derive(Debug, PartialEq, Eq, norito::SerializePayload, norito::json::JsonSerialize)]
pub struct PausePanelBody {
    pub(crate) panel_seq: u64,
    pub(crate) pulse_id: [u8; 32],
    pub(crate) seated_height: u64,
    pub(crate) seated_at_ms: u64,
    pub(crate) accept_until_ms: u64,
    pub(crate) term_ends_at_ms: u64,
    pub(crate) drawn: Vec<AccountId>,
    pub(crate) accepted: Vec<AccountId>,
    pub(crate) primary_id: [u8; 32],
    pub(crate) backup_id: [u8; 32],
}

/// Original funded panel graph. Canonical accepted ordering matches the Model BTreeSet.
#[derive(Clone)]
pub struct RetainedSccpPausePanel(ChargedShared<RetainedPayload<PausePanelBody>>);

impl RetainedSccpPausePanel {
    fn demand(source: &SccpPausePanelV1) -> Result<Demand, PauseRecordError> {
        if !source.has_valid_shape() {
            return Err(PauseRecordError::Invalid("panel structure"));
        }
        let mut demand = Demand::default();
        demand.array::<AccountId>(source.drawn.len())?;
        demand.array::<AccountId>(source.accepted.len())?;
        for account in source.drawn.iter().chain(source.accepted.iter()) {
            account_demand(&mut demand, account)?;
        }
        Ok(demand)
    }
    pub(crate) fn admission_demand(source: &SccpPausePanelV1) -> Result<usize, PauseRecordError> {
        Self::demand(source)?.total_bytes::<PausePanelBody>()
    }
    #[cfg(test)]
    pub(crate) fn admit(
        source: &SccpPausePanelV1,
        budget: &AllocationBudget,
    ) -> Result<Self, PauseRecordError> {
        let mut reservation = budget.try_reserve_bytes(Self::admission_demand(source)?)?;
        Self::admit_prepaid(source, budget, &mut reservation)
    }
    pub(crate) fn admit_prepaid(
        source: &SccpPausePanelV1,
        budget: &AllocationBudget,
        prepaid: &mut AllocationReservation,
    ) -> Result<Self, PauseRecordError> {
        let body = PausePanelBody {
            panel_seq: source.panel_seq,
            pulse_id: source.pulse_id,
            seated_height: source.seated_height,
            seated_at_ms: source.seated_at_ms,
            accept_until_ms: source.accept_until_ms,
            term_ends_at_ms: source.term_ends_at_ms,
            drawn: Vec::new(),
            accepted: Vec::new(),
            primary_id: source.primary_id,
            backup_id: source.backup_id,
        };
        let mut construction =
            Construction::new_prepaid(Self::demand(source)?, budget, prepaid, body)?;
        construction.body.drawn = construction.accounts(source.drawn.len(), &source.drawn)?;
        construction.body.accepted =
            construction.accounts(source.accepted.len(), &source.accepted)?;
        Ok(Self(publish(construction)?))
    }
}

/// Immutable endorsement entries, sorted by the canonical AccountId order.
#[derive(Debug, PartialEq, Eq)]
pub struct FastPauseRoundBody {
    pub(crate) panel_id: [u8; 32],
    pub(crate) panel_seq: u64,
    pub(crate) head: u64,
    pub(crate) opened_at_ms: u64,
    pub(crate) closes_at_ms: u64,
    pub(crate) endorsers: Vec<(AccountId, SccpFastPauseEndorsementV1)>,
    pub(crate) certify_due: bool,
}

/// Original funded endorsement round; cloning never rebuilds its account graph.
#[derive(Clone)]
pub struct RetainedSccpFastPauseRound(ChargedShared<RetainedPayload<FastPauseRoundBody>>);

impl RetainedSccpFastPauseRound {
    fn demand(source: &SccpFastPauseRoundV1) -> Result<Demand, PauseRecordError> {
        if !source.has_valid_shape() {
            return Err(PauseRecordError::Invalid("round structure"));
        }
        let mut demand = Demand::default();
        demand.array::<(AccountId, SccpFastPauseEndorsementV1)>(source.endorsers.len())?;
        for account in source.endorsers.keys() {
            account_demand(&mut demand, account)?;
        }
        Ok(demand)
    }
    pub(crate) fn admission_demand(
        source: &SccpFastPauseRoundV1,
    ) -> Result<usize, PauseRecordError> {
        Self::demand(source)?.total_bytes::<FastPauseRoundBody>()
    }
    #[cfg(test)]
    pub(crate) fn admit(
        source: &SccpFastPauseRoundV1,
        budget: &AllocationBudget,
    ) -> Result<Self, PauseRecordError> {
        let mut reservation = budget.try_reserve_bytes(Self::admission_demand(source)?)?;
        Self::admit_prepaid(source, budget, &mut reservation)
    }
    pub(crate) fn admit_prepaid(
        source: &SccpFastPauseRoundV1,
        budget: &AllocationBudget,
        prepaid: &mut AllocationReservation,
    ) -> Result<Self, PauseRecordError> {
        let body = FastPauseRoundBody {
            panel_id: source.panel_id,
            panel_seq: source.panel_seq,
            head: source.head,
            opened_at_ms: source.opened_at_ms,
            closes_at_ms: source.closes_at_ms,
            endorsers: Vec::new(),
            certify_due: source.certify_due,
        };
        let mut construction =
            Construction::new_prepaid(Self::demand(source)?, budget, prepaid, body)?;
        let mut entries =
            ChargedBuffer::from_reservation(source.endorsers.len(), &mut construction.reservation)
                .map_err(prepaid_error)?;
        for (account, value) in &source.endorsers {
            entries
                .try_push((construction.account(account)?, *value))
                .map_err(|_| PauseRecordError::Invalid("endorser count changed"))?;
        }
        construction.body.endorsers = construction.vector(entries)?;
        Ok(Self(publish(construction)?))
    }
}

struct Endorsements<'a>(&'a [(AccountId, SccpFastPauseEndorsementV1)]);
impl SerializePayload for Endorsements<'_> {
    fn serialize(&self, out: &mut Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_ordered_map_entries(
            out,
            self.0.len(),
            self.0.iter().map(|(key, value)| (key, value)),
        )
    }
}
impl JsonSerialize for Endorsements<'_> {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        for (index, (key, value)) in self.0.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            // AccountId's JSON value and object-key contracts both emit the same canonical
            // I105 string. This concrete projection never substitutes arbitrary JSON values.
            key.json_serialize(out);
            out.push(':');
            value.json_serialize(out);
        }
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| {
            out.push('{')?;
            for (index, (key, value)) in self.0.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                key.json_serialize_to(out)?;
                out.push(':')?;
                value.json_serialize_to(out)?;
            }
            out.push('}')
        })();
        out.end_container();
        result
    }
}
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
struct RoundView<'a> {
    panel_id: [u8; 32],
    panel_seq: u64,
    head: u64,
    opened_at_ms: u64,
    closes_at_ms: u64,
    endorsers: Endorsements<'a>,
    certify_due: bool,
}
impl FastPauseRoundBody {
    fn view(&self) -> RoundView<'_> {
        RoundView {
            panel_id: self.panel_id,
            panel_seq: self.panel_seq,
            head: self.head,
            opened_at_ms: self.opened_at_ms,
            closes_at_ms: self.closes_at_ms,
            endorsers: Endorsements(&self.endorsers),
            certify_due: self.certify_due,
        }
    }
}
impl SerializePayload for FastPauseRoundBody {
    fn serialize(&self, out: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.view().serialize(out)
    }
}
impl JsonSerialize for FastPauseRoundBody {
    fn json_serialize(&self, out: &mut String) {
        self.view().json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.view().json_serialize_to(out)
    }
}

macro_rules! retained_traits {
    ($owner:ty, $body:ty, $dto:ty) => {
        impl Deref for $owner {
            type Target = $body;
            fn deref(&self) -> &Self::Target {
                self.0.get()
            }
        }
        impl fmt::Debug for $owner {
            fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.get().fmt(out)
            }
        }
        impl PartialEq for $owner {
            fn eq(&self, other: &Self) -> bool {
                self.0.get() == other.0.get()
            }
        }
        impl Eq for $owner {}
        impl norito::NoritoSchema for $owner {
            fn nominal_name() -> String {
                <$dto as norito::NoritoSchema>::nominal_name()
            }
            fn frame_name() -> String {
                <$dto as norito::NoritoSchema>::frame_name()
            }
        }
        impl SerializePayload for $owner {
            fn serialize(&self, out: &mut Encoder<'_>) -> Result<(), norito::Error> {
                self.0.get().serialize(out)
            }
        }
        impl JsonSerialize for $owner {
            fn json_serialize(&self, out: &mut String) {
                self.0.get().json_serialize(out);
            }
            fn json_serialize_to(
                &self,
                out: &mut dyn json::JsonWriteSink,
            ) -> Result<(), json::BoundedJsonError> {
                self.0.get().json_serialize_to(out)
            }
        }
    };
}
retained_traits!(RetainedSccpFastPause, SccpFastPauseV1, SccpFastPauseV1);
retained_traits!(RetainedSccpPausePanel, PausePanelBody, SccpPausePanelV1);
retained_traits!(
    RetainedSccpFastPauseRound,
    FastPauseRoundBody,
    SccpFastPauseRoundV1
);

#[cfg(test)]
mod tests;
