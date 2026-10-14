//! Original-pool backing for mutable DKG rows and immutable public projections.

use super::*;
use crate::beacon::{
    GlobalThresholdBeaconDkgSnapshotV1, GlobalThresholdBeaconError,
    GlobalThresholdBeaconSessionError,
    validation::{DkgSignaturePreimage, DkgSignatureVerifier, DkgSnapshotRef},
};
use iroha_data_model::consensus::GlobalThresholdBeaconDkgSessionV1;
use norito::{codec::Encode as _, core::SerializePayload};

mod pending;
pub(in crate::beacon) use pending::PendingRow;

/// One canonical DKG row and the exact nested backing built by the existing materializer.
pub(in crate::beacon) trait DkgRow: Sized {
    type Key: Copy + Ord;
    fn key(&self) -> Self::Key;
    fn demand(&self, demand: &mut Demand) -> Result<(), SessionGraphError>;
    fn materialize(
        &self,
        construction: &mut Construction<'_, '_>,
    ) -> Result<Self, SessionGraphError>;
}
impl DkgRow for GlobalThresholdBeaconDkgRecipientKeyV1 {
    type Key = u16;
    fn key(&self) -> u16 {
        self.recipient_index
    }
    fn demand(&self, demand: &mut Demand) -> Result<(), SessionGraphError> {
        demand.add(self.validator.public_key().retained_allocation_layout())?;
        demand.array::<u8>(self.mlkem768_public_key.len())?;
        demand.add(self.signature.retained_allocation_layout())
    }
    fn materialize(
        &self,
        construction: &mut Construction<'_, '_>,
    ) -> Result<Self, SessionGraphError> {
        construction.recipient(self)
    }
}
impl DkgRow for GlobalThresholdBeaconDkgDealerCommitmentV1 {
    type Key = u16;
    fn key(&self) -> u16 {
        self.dealer_index
    }
    fn demand(&self, demand: &mut Demand) -> Result<(), SessionGraphError> {
        demand.array::<[u8; 96]>(self.coefficient_commitments.len())?;
        demand.add(self.signature.retained_allocation_layout())
    }
    fn materialize(
        &self,
        construction: &mut Construction<'_, '_>,
    ) -> Result<Self, SessionGraphError> {
        construction.dealer(self)
    }
}
impl DkgRow for GlobalThresholdBeaconDkgEncryptedShareV1 {
    type Key = (u16, u16);
    fn key(&self) -> Self::Key {
        (self.dealer_index, self.recipient_index)
    }
    fn demand(&self, demand: &mut Demand) -> Result<(), SessionGraphError> {
        demand.array::<u8>(self.mlkem768_ciphertext.len())?;
        demand.array::<u8>(self.encrypted_share.len())?;
        demand.add(self.signature.retained_allocation_layout())
    }
    fn materialize(
        &self,
        construction: &mut Construction<'_, '_>,
    ) -> Result<Self, SessionGraphError> {
        construction.edge(self)
    }
}
impl DkgRow for GlobalThresholdBeaconDkgShareAcceptanceV1 {
    type Key = (u16, u16);
    fn key(&self) -> Self::Key {
        (self.dealer_index, self.recipient_index)
    }
    fn demand(&self, demand: &mut Demand) -> Result<(), SessionGraphError> {
        demand.add(self.signature.retained_allocation_layout())
    }
    fn materialize(
        &self,
        construction: &mut Construction<'_, '_>,
    ) -> Result<Self, SessionGraphError> {
        construction.acceptance(self)
    }
}

/// Sorted bounded rows; every nested payload remains attached to its exact original ledger.
pub(in crate::beacon) struct DkgRows<T: DkgRow> {
    rows: ChargedBuffer<RetainedPayload<T>>,
}
impl<T: DkgRow + std::fmt::Debug> std::fmt::Debug for DkgRows<T> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_list().entries(self.values()).finish()
    }
}
impl<T: DkgRow> DkgRows<T> {
    pub(in crate::beacon) fn layout(capacity: usize) -> Result<Layout, SessionGraphError> {
        Layout::array::<RetainedPayload<T>>(capacity)
            .map_err(|_| AllocationRefusal::DemandOverflow.into())
    }
    pub(in crate::beacon) fn from_reservation(
        capacity: usize,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, SessionGraphError> {
        Ok(Self {
            rows: ChargedBuffer::from_reservation(capacity, reservation)?,
        })
    }
    pub(in crate::beacon) fn len(&self) -> usize {
        self.rows.as_slice().len()
    }
    pub(in crate::beacon) fn values(
        &self,
    ) -> impl ExactSizeIterator<Item = &T> + DoubleEndedIterator + Clone {
        self.rows.as_slice().iter().map(RetainedPayload::get)
    }
    pub(in crate::beacon) fn get(&self, key: &T::Key) -> Option<&T> {
        self.rows
            .as_slice()
            .binary_search_by_key(key, |row| row.get().key())
            .ok()
            .map(|index| self.rows.as_slice()[index].get())
    }
    pub(in crate::beacon) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.rows.belongs_to(budget)
            && self
                .rows
                .as_slice()
                .iter()
                .all(|row| row.belongs_to(budget))
    }
    pub(in crate::beacon) fn insert(
        &mut self,
        source: &T,
        budget: &AllocationBudget,
    ) -> Result<(), SessionGraphError> {
        if !self.rows.belongs_to(budget) {
            return Err(RetainedPayloadError::ForeignLedger.into());
        }
        let position = self
            .rows
            .as_slice()
            .binary_search_by_key(&source.key(), |row| row.get().key())
            .err()
            .ok_or(SessionGraphError::PlanChanged)?;
        if self.rows.as_slice().len() == self.rows.capacity() {
            return Err(SessionGraphError::PlanChanged);
        }
        let mut demand = Demand::default();
        source.demand(&mut demand)?;
        let mut reservation = budget.try_reserve_bytes(demand.total_bytes()?)?;
        let mut construction = Construction::with_demand(demand, budget, &mut reservation)?;
        let row = source.materialize(&mut construction)?;
        let owner = construction.finish(row)?;
        if construction.reservation.remaining_bytes() != 0 {
            return Err(SessionGraphError::PlanChanged);
        }
        self.rows.push_reserved(owner);
        self.rows.as_mut_slice()[position..].rotate_right(1);
        Ok(())
    }
}

/// Immutable canonical snapshot retaining all exact original row/vector/key/signature backing.
///
/// No clone, mutable accessor or DTO extraction may separate this graph from its ledger.
pub struct RetainedGlobalThresholdBeaconDkgSnapshotV1 {
    owner: RetainedPayload<GlobalThresholdBeaconDkgSnapshotV1>,
}
impl RetainedGlobalThresholdBeaconDkgSnapshotV1 {
    /// Borrow the sole canonical persistence projection.
    pub fn record(&self) -> &GlobalThresholdBeaconDkgSnapshotV1 {
        self.owner.get()
    }
    /// Verify identity of the original operation pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.owner.belongs_to(budget)
    }
    pub(in crate::beacon) fn from_rows(
        session: GlobalThresholdBeaconDkgSessionV1,
        generator_h: [u8; 96],
        generator_v: [u8; 96],
        recipient_keys: &DkgRows<GlobalThresholdBeaconDkgRecipientKeyV1>,
        dealer_commitments: &DkgRows<GlobalThresholdBeaconDkgDealerCommitmentV1>,
        encrypted_shares: &DkgRows<GlobalThresholdBeaconDkgEncryptedShareV1>,
        share_acceptances: &DkgRows<GlobalThresholdBeaconDkgShareAcceptanceV1>,
        last_updated_height: u64,
        budget: &AllocationBudget,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        if !recipient_keys.belongs_to(budget)
            || !dealer_commitments.belongs_to(budget)
            || !encrypted_shares.belongs_to(budget)
            || !share_acceptances.belongs_to(budget)
        {
            return Err(GlobalThresholdBeaconSessionError::ForeignReservation);
        }
        let mut demand = Demand::default();
        demand.array::<GlobalThresholdBeaconDkgRecipientKeyV1>(recipient_keys.len())?;
        for row in recipient_keys.values() {
            row.demand(&mut demand)?;
        }
        demand.array::<GlobalThresholdBeaconDkgDealerCommitmentV1>(dealer_commitments.len())?;
        for row in dealer_commitments.values() {
            row.demand(&mut demand)?;
        }
        demand.array::<GlobalThresholdBeaconDkgEncryptedShareV1>(encrypted_shares.len())?;
        for row in encrypted_shares.values() {
            row.demand(&mut demand)?;
        }
        demand.array::<GlobalThresholdBeaconDkgShareAcceptanceV1>(share_acceptances.len())?;
        for row in share_acceptances.values() {
            row.demand(&mut demand)?;
        }
        let mut reservation = budget.try_reserve_bytes(demand.total_bytes()?)?;
        let mut construction = Construction::with_demand(demand, budget, &mut reservation)?;
        let recipient_keys = construction.recipients(recipient_keys.values())?;
        let dealer_commitments = construction.dealers(dealer_commitments.values())?;
        let encrypted_shares = construction.edges(encrypted_shares.values())?;
        let share_acceptances = construction.acceptances(share_acceptances.values())?;
        let owner = construction.finish(GlobalThresholdBeaconDkgSnapshotV1 {
            session,
            generator_h,
            generator_v,
            recipient_keys,
            dealer_commitments,
            encrypted_shares,
            share_acceptances,
            last_updated_height,
        })?;
        if construction.reservation.remaining_bytes() != 0 {
            return Err(GlobalThresholdBeaconSessionError::PlanChanged);
        }
        Ok(Self { owner })
    }
}
impl std::ops::Deref for RetainedGlobalThresholdBeaconDkgSnapshotV1 {
    type Target = GlobalThresholdBeaconDkgSnapshotV1;
    fn deref(&self) -> &Self::Target {
        self.record()
    }
}
impl std::fmt::Debug for RetainedGlobalThresholdBeaconDkgSnapshotV1 {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.record().fmt(out)
    }
}
impl norito::NoritoSchema for RetainedGlobalThresholdBeaconDkgSnapshotV1 {
    fn nominal_name() -> String {
        <GlobalThresholdBeaconDkgSnapshotV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <GlobalThresholdBeaconDkgSnapshotV1 as norito::NoritoSchema>::frame_name()
    }
    fn static_nominal_name() -> Option<&'static str> {
        <GlobalThresholdBeaconDkgSnapshotV1 as norito::NoritoSchema>::static_nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        <GlobalThresholdBeaconDkgSnapshotV1 as norito::NoritoSchema>::static_frame_name()
    }
}
impl SerializePayload for RetainedGlobalThresholdBeaconDkgSnapshotV1 {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.record().serialize(out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.record().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.record().encoded_len_exact()
    }
}

/// Reusable exact physical message buffer for the existing DKG signature verifier.
pub(in crate::beacon) struct DkgMessageWorkspace {
    bytes: ChargedBuffer<u8>,
}
impl DkgMessageWorkspace {
    /// Physical bound derived from the canonical authenticated local row shapes.
    pub(in crate::beacon) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }
    pub(in crate::beacon) fn new(
        size: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, SessionGraphError> {
        let mut reservation = budget.try_reserve(
            Layout::array::<u8>(size).map_err(|_| AllocationRefusal::DemandOverflow)?,
        )?;
        Ok(Self {
            bytes: ChargedBuffer::from_reservation(size, &mut reservation)?,
        })
    }
    pub(in crate::beacon) fn write(
        &mut self,
        preimage: DkgSignaturePreimage<'_>,
    ) -> Result<&[u8], SessionGraphError> {
        self.bytes.truncate(0);
        let expected = preimage.encoded_len();
        if expected > self.bytes.capacity() {
            return Err(SessionGraphError::PlanChanged);
        }
        norito::codec::encode_adaptive_into(&preimage, &mut ChargedBytesWriter(&mut self.bytes))?;
        if self.bytes.as_slice().len() != expected {
            return Err(SessionGraphError::PlanChanged);
        }
        Ok(self.bytes.as_slice())
    }
    pub(in crate::beacon) fn for_snapshot(
        source: &GlobalThresholdBeaconDkgSnapshotV1,
        budget: &AllocationBudget,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        DkgSnapshotRef::from(source).validate_bounds()?;
        let mut max = 0;
        for row in &source.recipient_keys {
            max = max.max(DkgSignaturePreimage::RecipientKey(&source.session, row).encoded_len());
        }
        for row in &source.dealer_commitments {
            max =
                max.max(DkgSignaturePreimage::DealerCommitment(&source.session, row).encoded_len());
        }
        for row in &source.encrypted_shares {
            max = max.max(DkgSignaturePreimage::EncryptedShare(&source.session, row).encoded_len());
        }
        for row in &source.share_acceptances {
            max =
                max.max(DkgSignaturePreimage::ShareAcceptance(&source.session, row).encoded_len());
        }
        Self::new(max, budget).map_err(Into::into)
    }
}
impl DkgSignatureVerifier for DkgMessageWorkspace {
    type Resource = SessionGraphError;
    fn verify(
        &mut self,
        preimage: DkgSignaturePreimage<'_>,
        signature: &Signature,
        key: &PublicKey,
    ) -> Result<bool, Self::Resource> {
        Ok(iroha_crypto::verify_signature_borrowed(signature, key, self.write(preimage)?).is_ok())
    }
}

pub(in crate::beacon) fn validate_dkg_recipient_bounds(
    session: &GlobalThresholdBeaconDkgSessionV1,
    row: &GlobalThresholdBeaconDkgRecipientKeyV1,
) -> Result<(), GlobalThresholdBeaconError> {
    crate::beacon::validate_participant(session, row.recipient_index)?;
    if row.validator.public_key().algorithm() != iroha_crypto::Algorithm::BlsNormal
        || row.mlkem768_public_key.len() != soranet_pq::MlKemSuite::MlKem768.public_key_len()
        || row.signature.payload().len()
            != iroha_crypto::Algorithm::BlsNormal.signature_payload_len()
    {
        return Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey);
    }
    Ok(())
}
pub(in crate::beacon) fn validate_dkg_dealer_bounds(
    session: &GlobalThresholdBeaconDkgSessionV1,
    row: &GlobalThresholdBeaconDkgDealerCommitmentV1,
) -> Result<(), GlobalThresholdBeaconError> {
    crate::beacon::validate_participant(session, row.dealer_index)?;
    if row.coefficient_commitments.len() != usize::from(session.threshold)
        || row.signature.payload().len()
            != iroha_crypto::Algorithm::BlsNormal.signature_payload_len()
    {
        return Err(GlobalThresholdBeaconError::DealerCommitmentEquivocation);
    }
    Ok(())
}
pub(in crate::beacon) fn validate_dkg_edge_bounds(
    row: &GlobalThresholdBeaconDkgEncryptedShareV1,
) -> Result<(), GlobalThresholdBeaconError> {
    if row.mlkem768_ciphertext.len() != soranet_pq::MlKemSuite::MlKem768.ciphertext_len()
        || row.encrypted_share.len() != 12 + 96 + 16
        || row.signature.payload().len()
            != iroha_crypto::Algorithm::BlsNormal.signature_payload_len()
    {
        return Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare);
    }
    Ok(())
}
pub(in crate::beacon) fn validate_dkg_acceptance_bounds(
    row: &GlobalThresholdBeaconDkgShareAcceptanceV1,
) -> Result<(), GlobalThresholdBeaconError> {
    if row.signature.payload().len() != iroha_crypto::Algorithm::BlsNormal.signature_payload_len() {
        return Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance);
    }
    Ok(())
}

pub(in crate::beacon) fn retain_finalized_dkg(
    source: &GlobalThresholdBeaconDkgSnapshotV1,
    qualified_dealers: &[u16],
    event_hash: [u8; 32],
    height: u64,
    derived: &crate::beacon::GlobalThresholdBeaconDkgDerivedPublicV1,
    budget: &AllocationBudget,
) -> Result<RetainedPayload<GlobalThresholdBeaconKeySessionV1>, GlobalThresholdBeaconSessionError> {
    let mut demand = Demand::default();
    demand.array::<GlobalThresholdBeaconPublicShareV1>(derived.public_shares.len())?;
    demand.array::<u16>(qualified_dealers.len())?;
    demand.array::<GlobalThresholdBeaconDkgRecipientKeyV1>(source.recipient_keys.len())?;
    for row in &source.recipient_keys {
        row.demand(&mut demand)?;
    }
    demand.array::<GlobalThresholdBeaconDkgDealerCommitmentV1>(source.dealer_commitments.len())?;
    for row in &source.dealer_commitments {
        row.demand(&mut demand)?;
    }
    demand.array::<GlobalThresholdBeaconDkgEncryptedShareV1>(source.encrypted_shares.len())?;
    for row in &source.encrypted_shares {
        row.demand(&mut demand)?;
    }
    demand.array::<GlobalThresholdBeaconDkgShareAcceptanceV1>(source.share_acceptances.len())?;
    for row in &source.share_acceptances {
        row.demand(&mut demand)?;
    }
    let mut reservation = budget.try_reserve_bytes(demand.total_bytes()?)?;
    let mut construction = Construction::with_demand(demand, budget, &mut reservation)?;
    let public_shares = construction.copied(&derived.public_shares)?;
    let qualified_dealers = construction.copied(qualified_dealers)?;
    let recipient_keys = construction.recipients(source.recipient_keys.iter())?;
    let dealer_commitments = construction.dealers(source.dealer_commitments.iter())?;
    let encrypted_shares = construction.edges(source.encrypted_shares.iter())?;
    let share_acceptances = construction.acceptances(source.share_acceptances.iter())?;
    let adaptive_dkg = GlobalThresholdBeaconDkgTranscriptV1 {
        session: source.session,
        generator_h: source.generator_h,
        generator_v: source.generator_v,
        dealer_commitments,
        recipient_keys,
        encrypted_shares,
        share_acceptances,
        qualified_dealers,
        event_hash,
        finalized_at_height: height,
    };
    let owner = construction.finish(GlobalThresholdBeaconKeySessionV1 {
        version: source.session.version,
        network_id: source.session.network_id,
        session_id: source.session.session_id,
        roster_hash: source.session.roster_hash,
        committee_size: source.session.committee_size,
        threshold: source.session.threshold,
        group_public_key: derived.group_public_key,
        public_shares,
        adaptive_dkg,
        dkg_contribution_hash: event_hash,
        transcript_hash: derived.transcript_hash,
    })?;
    if construction.reservation.remaining_bytes() != 0 {
        return Err(GlobalThresholdBeaconSessionError::PlanChanged);
    }
    Ok(owner)
}

/// Move-only completed DKG graph retaining the reducer's exact original nested allocations.
pub struct RetainedGlobalThresholdBeaconDkgFinalizationV1 {
    pub(in crate::beacon) owner: RetainedPayload<GlobalThresholdBeaconKeySessionV1>,
}
impl RetainedGlobalThresholdBeaconDkgFinalizationV1 {
    /// Borrow the completed canonical record without detaching its allocation ledger.
    pub fn record(&self) -> &GlobalThresholdBeaconKeySessionV1 {
        self.owner.get()
    }
    /// Check the exact caller allocation source.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.owner.belongs_to(budget)
    }
}
impl std::ops::Deref for RetainedGlobalThresholdBeaconDkgFinalizationV1 {
    type Target = GlobalThresholdBeaconKeySessionV1;
    fn deref(&self) -> &Self::Target {
        self.record()
    }
}
impl std::fmt::Debug for RetainedGlobalThresholdBeaconDkgFinalizationV1 {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.record().fmt(out)
    }
}
impl norito::NoritoSchema for RetainedGlobalThresholdBeaconDkgFinalizationV1 {
    fn nominal_name() -> String {
        <GlobalThresholdBeaconKeySessionV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <GlobalThresholdBeaconKeySessionV1 as norito::NoritoSchema>::frame_name()
    }
    fn static_nominal_name() -> Option<&'static str> {
        <GlobalThresholdBeaconKeySessionV1 as norito::NoritoSchema>::static_nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        <GlobalThresholdBeaconKeySessionV1 as norito::NoritoSchema>::static_frame_name()
    }
}
impl SerializePayload for RetainedGlobalThresholdBeaconDkgFinalizationV1 {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.record().serialize(out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.record().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.record().encoded_len_exact()
    }
}

#[cfg(test)]
mod tests;
