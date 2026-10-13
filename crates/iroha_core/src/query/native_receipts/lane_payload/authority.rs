//! Prepaid selected native authority, borrowing the original creation corpus and proofs.
//!
//! No full lane/World graph is decoded. Only the selected core committee and epoch acquire
//! new storage. PoPs and unused parameter fields remain in the original authenticated bytes.
//! Cryptographic admission caches and the original source decoder remain separate owners.

mod raw;
use raw::RawAuthority;

use std::alloc::Layout;

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    RetainedPayload,
};
use iroha_data_model::sumeragi_lanes::SumeragiLaneFrontier;
use iroha_model_base::topology::LaneId;
use iroha_sumeragi::types::{Committee, EpochConfig, EpochId, Hash32, HeightConfig, PublicKey};

use super::{LanePayload, LanePayloadError};

/// Original creation bytes and immutable selected incarnation, preserved across local refusal.
pub(crate) struct LaneAuthorityRead {
    source: LanePayload,
    incarnation: [u8; 32],
}
impl LaneAuthorityRead {
    pub(crate) fn new(source: LanePayload, incarnation: [u8; 32]) -> Self {
        Self {
            source,
            incarnation,
        }
    }

    fn prepare_source(
        source: &LanePayload,
        incarnation: &[u8; 32],
        budget: &AllocationBudget,
    ) -> Result<AuthorityConfig, LanePayloadError> {
        if !source.belongs_to(budget) {
            return Err(LanePayloadError::Source);
        }
        let encoded = source
            .lane_record(incarnation)?
            .ok_or(LanePayloadError::Source)?;
        let raw = RawAuthority::parse(encoded)?;
        if raw.created != source.carrier().1 {
            return Err(LanePayloadError::Source);
        }
        let context = raw.context()?;
        let genesis = SumeragiLaneFrontier {
            height: 0,
            block_hash: iroha_crypto::Hash::new_from_chunks(&[
                crate::sumeragi::lanes::LANE_GENESIS_TAG,
                source.carrier().0.as_bytes(),
                &raw.lane.as_u32().to_be_bytes(),
                incarnation,
            ])
            .into(),
            result: context.0,
        };
        if raw.frontier()? != genesis {
            return Err(LanePayloadError::Source);
        }
        let demand = raw.demand()?;
        // Construction is declared before every detached value, so its ledger outlives all
        // payload destruction on ordinary failure. An unwind conservatively retains credit.
        let mut construction = Construction::new(demand, budget)?;
        let mut members =
            ChargedBuffer::from_reservation(raw.count, &mut construction.reservation)?;
        raw.visit(|key, _pop| {
            let mut bytes =
                ChargedBuffer::from_reservation(key.len(), &mut construction.reservation)?;
            bytes.append(key).map_err(|_| LanePayloadError::Source)?;
            let key = PublicKey::new(construction.vector(bytes)?)
                .map_err(|_| LanePayloadError::Source)?;
            members
                .try_push(key)
                .map_err(|_| LanePayloadError::Source)?;
            Ok(())
        })?;
        let committee =
            Committee::new(construction.vector(members)?).map_err(|_| LanePayloadError::Source)?;
        let epoch = construction.epoch(EpochConfig {
            da_layout: raw.layout,
            id: EpochId { epoch: 0, context },
            authority_generation: context,
            first_height: 0,
            last_height: u64::MAX,
            leader_seed: context,
        })?;
        let config = HeightConfig {
            epoch,
            committee,
            params: raw.params.to_core(),
        };
        let config = construction.finish(config, budget)?;
        Ok(AuthorityConfig {
            config,
            lane: raw.lane,
            genesis,
            demotion_window: raw.demotion_window,
        })
    }

    fn prepare(&self, budget: &AllocationBudget) -> Result<AuthorityConfig, LanePayloadError> {
        Self::prepare_source(&self.source, &self.incarnation, budget)
    }

    /// Retain the same source and selection on every error; no graph is allocated before its
    /// complete exact demand is admitted. Success keeps both source and destination custody.
    #[expect(
        clippy::result_large_err,
        reason = "return the original funded creation source without allocating on refusal"
    )]
    pub(crate) fn complete(
        self,
        budget: &AllocationBudget,
    ) -> Result<LaneAuthority, (Self, LanePayloadError)> {
        match self.prepare(budget) {
            Ok(authority) => Ok(LaneAuthority {
                source: self.source,
                incarnation: self.incarnation,
                authority,
            }),
            Err(error) => Err((self, error)),
        }
    }
}

struct AuthorityConfig {
    config: RetainedPayload<HeightConfig>,
    lane: LaneId,
    genesis: SumeragiLaneFrontier,
    demotion_window: u64,
}

/// Exact prepaid selected configuration and original immutable creation/proof bytes.
/// This is a configuration owner, not a PoP verification cache or monetary admission.
pub(crate) struct LaneAuthority {
    source: LanePayload,
    incarnation: [u8; 32],
    authority: AuthorityConfig,
}
impl std::borrow::Borrow<HeightConfig> for LaneAuthority {
    fn borrow(&self) -> &HeightConfig {
        self.config()
    }
}
impl LaneAuthority {
    pub(crate) fn genesis(&self) -> SumeragiLaneFrontier {
        self.authority.genesis
    }
    /// The native instance's immutable demotion constant from its actual creation record.
    pub(crate) fn demotion_window(&self) -> u64 {
        self.authority.demotion_window
    }
    /// Original root creation height, distinct from any native subject height.
    pub(crate) fn created_at(&self) -> u64 {
        self.source.carrier().1
    }
    pub(crate) fn config(&self) -> &HeightConfig {
        self.authority.config.get()
    }
    pub(crate) fn lane(&self) -> LaneId {
        self.authority.lane
    }
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.source.belongs_to(budget) && self.authority.config.belongs_to(budget)
    }
    /// Acquire a second exact configuration from these same original creation bytes. No
    /// generic clone occurs; every key/vector/epoch and ledger allocation is prepaid in the
    /// same source pool before materialization. Refusal keeps this original authority intact.
    pub(crate) fn copy_config(
        &self,
        budget: &AllocationBudget,
    ) -> Result<RetainedPayload<HeightConfig>, LanePayloadError> {
        if !self.belongs_to(budget) {
            return Err(LanePayloadError::Source);
        }
        LaneAuthorityRead::prepare_source(&self.source, &self.incarnation, budget)
            .map(|authority| authority.config)
    }

    /// Verify the latest retained custody against this exact original creation. Historical
    /// store reads may outlive custody reclamation; absence grants no stake authority. Every
    /// present row must retain its creation-time signer bindings and immutable signed policy.
    pub(crate) fn validate_custody(
        &self,
        current: &LanePayload,
        instance: Hash32,
        policy: Option<(u64, u64)>,
        budget: &AllocationBudget,
    ) -> Result<(), LanePayloadError> {
        if !self.belongs_to(budget) || !current.belongs_to(budget) {
            return Err(LanePayloadError::Source);
        }
        if current.carrier().0 != self.source.carrier().0
            || current.carrier().1 < self.source.carrier().1
        {
            return Err(LanePayloadError::Source);
        }
        let Some(current_row) = current.custody_record(&self.incarnation)? else {
            return Ok(());
        };
        let original = self
            .source
            .custody_record(&self.incarnation)?
            .ok_or(LanePayloadError::Source)?;
        let identity = (
            self.lane(),
            self.incarnation,
            instance.0,
            self.source.carrier().1,
        );
        let (count, horizon, delay, retired) = original.policy();
        let (current_count, current_horizon, current_delay, current_retired) = current_row.policy();
        let genesis_matches = original.frontier() == self.genesis();
        if original.identity() != identity
            || current_row.identity() != identity
            || usize::try_from(count).ok() != Some(self.config().committee.n())
            || current_count != count
            || retired.is_some()
            || policy != Some((horizon, delay))
            || (current_horizon, current_delay) != (horizon, delay)
            || current_retired.is_some_and(|retired| retired > current.carrier().1)
            || !genesis_matches
            || (current_row.frontier().height == 0 && current_row.frontier() != original.frontier())
        {
            return Err(LanePayloadError::Source);
        }
        for signer in 0..count {
            if original.binding(signer)? != current_row.binding(signer)? {
                return Err(LanePayloadError::Source);
            }
        }
        Ok(())
    }

    /// Inspect exact original key/proof bytes without allocating a second credential graph.
    /// The key borrow lasts only for this callback; its canonical compact encoding is scanned
    /// into bounded stack storage. PoPs borrow the original retained creation record.
    pub(crate) fn visit_members<'a>(
        &'a self,
        mut visit: impl FnMut(&[u8], &'a [u8]) -> Result<(), LanePayloadError>,
    ) -> Result<(), LanePayloadError> {
        let encoded = self
            .source
            .lane_record(&self.incarnation)?
            .ok_or(LanePayloadError::Source)?;
        RawAuthority::parse(encoded)?.visit(|key, pop| visit(key, pop))
    }
}

fn array<T>(length: usize) -> Result<Layout, AllocationRefusal> {
    Layout::array::<T>(length).map_err(|_| AllocationRefusal::DemandOverflow)
}
struct Demand {
    bytes: usize,
    charges: usize,
}
struct Construction {
    reservation: AllocationReservation,
    charges: Option<ChargedBuffer<AllocationCharge>>,
}
impl Drop for Construction {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(charges) = self.charges.take() {
                std::mem::forget(charges);
            }
        }
    }
}
impl Construction {
    fn new(demand: Demand, budget: &AllocationBudget) -> Result<Self, LanePayloadError> {
        let mut reservation = budget.try_reserve_bytes(demand.bytes)?;
        let charges = ChargedBuffer::from_reservation(demand.charges, &mut reservation)?;
        Ok(Self {
            reservation,
            charges: Some(charges),
        })
    }
    #[allow(
        unsafe_code,
        reason = "exact canonical fields retain their original ledger until destruction"
    )]
    fn vector<T>(&mut self, original: ChargedBuffer<T>) -> Result<Vec<T>, LanePayloadError> {
        // SAFETY: every caller immediately moves the exact backing into an immutable field
        // declared after this construction guard. No capacity mutation or escape is exposed.
        let (values, charge) = unsafe { original.into_allocation_parts() };
        if let Err(charge) = self
            .charges
            .as_mut()
            .expect("construction ledger")
            .try_push(charge)
        {
            std::mem::forget(charge);
            return Err(LanePayloadError::Source);
        }
        Ok(values)
    }
    #[allow(
        unsafe_code,
        reason = "one prepaid epoch allocation moves unchanged into its canonical Box"
    )]
    fn epoch(&mut self, epoch: EpochConfig) -> Result<Box<EpochConfig>, LanePayloadError> {
        let mut original = ChargedBuffer::from_reservation(1, &mut self.reservation)?;
        original
            .try_push(epoch)
            .map_err(|_| LanePayloadError::Source)?;
        let values = self.vector(original)?;
        // SAFETY: length and capacity are exactly one; into_boxed_slice cannot resize.
        // A one-element slice has the same layout as its element. The immutable returned
        // epoch stays paired with this guard's exact charge, including all failure paths.
        let pointer = Box::into_raw(values.into_boxed_slice()).cast::<EpochConfig>();
        Ok(unsafe { Box::from_raw(pointer) })
    }
    #[allow(
        unsafe_code,
        reason = "all selected config allocations are exact prepaid immutable fields"
    )]
    fn finish(
        mut self,
        config: HeightConfig,
        budget: &AllocationBudget,
    ) -> Result<RetainedPayload<HeightConfig>, LanePayloadError> {
        if self.reservation.remaining_bytes() != 0 {
            drop(config);
            return Err(LanePayloadError::Source);
        }
        let charges = self.charges.take().expect("complete construction ledger");
        // SAFETY: each committee/key backing and the sole epoch Box is immutable, was
        // allocated from an exact split above, and has exactly one original ledger entry.
        match unsafe { RetainedPayload::try_new(config, charges, budget) } {
            Ok(owner) => Ok(owner),
            Err((config, charges, _)) => {
                drop(config);
                drop(charges);
                Err(LanePayloadError::Source)
            }
        }
    }
}

#[cfg(test)]
mod tests;
