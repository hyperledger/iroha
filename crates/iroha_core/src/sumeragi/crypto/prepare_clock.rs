//! Original execution clocks sampled at the native Prepare signature boundary.
//!
//! The worker publishes only fixed observations of its actual completed executions. The
//! signer consumes the Core's authenticated current certification context independently:
//! a saved Prepare reservation or an earlier `Execute.certified` bit grants no exemption.

use super::KeyPairSigner;
use crate::smartcontracts::isi::sccp::keepalive::ProgressClock;
use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedShared, PrepaidSharedError};
use iroha_primitives::time::TimeSource;
use iroha_sumeragi::{
    crypto::{PrepareSigningContext, Signer, SigningError},
    message::BlockHeader,
    types::{EpochId, Hash32, PublicKey, Signature},
};
use parking_lot::Mutex;

// Same finite per-height bound as the native executor's completed-result cache. Missing or
// evicted observations refuse locally; neither guessed timestamps nor current World replace
// the original parent observation. The next actual execution can install it again.
const OBSERVATIONS: usize = 16;

#[derive(Clone, Copy)]
struct Observation {
    instance: Hash32,
    epoch: EpochId,
    height: u64,
    block_hash: Hash32,
    result: Hash32,
    clock: Option<ProgressClock>,
}

struct Observations {
    entries: [Option<Observation>; OBSERVATIONS],
    next: usize,
}

struct SharedClock {
    observations: Mutex<Observations>,
    time: TimeSource,
}

/// One bounded, original-State-funded execution/signature handoff.
#[derive(Clone)]
pub(crate) struct PrepareClock(ChargedShared<SharedClock>);

/// Admission fails before retaining any clock publication channel.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PrepareClockError {
    /// Refusal from the original State allocation pool.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Physical allocation of the already prepaid fixed owner failed.
    #[error(transparent)]
    Allocation(PrepaidSharedError),
}

impl PrepareClock {
    #[cfg(test)]
    pub(crate) fn authorize_uncertified_for_test(
        &self,
        header: &BlockHeader,
        block_hash: Hash32,
        result: Hash32,
    ) -> Result<(), SigningError> {
        self.authorize(
            header.instance,
            header.epoch,
            header.height,
            block_hash,
            result,
            false,
        )
    }

    pub(crate) fn new(
        budget: &AllocationBudget,
        time: TimeSource,
    ) -> Result<Self, PrepareClockError> {
        let mut reservation =
            budget.try_reserve(ChargedShared::<SharedClock>::allocation_layout())?;
        let shared = SharedClock {
            observations: Mutex::new(Observations {
                entries: [None; OBSERVATIONS],
                next: 0,
            }),
            time,
        };
        ChargedShared::from_reservation(shared, &mut reservation)
            .map(Self)
            .map_err(|(_, error)| PrepareClockError::Allocation(error))
    }

    /// Publish only after the original worker has produced the exact result for this body.
    pub(crate) fn record(
        &self,
        header: &BlockHeader,
        block_hash: Hash32,
        result: Hash32,
        clock: Option<ProgressClock>,
    ) {
        let observation = Observation {
            instance: header.instance,
            epoch: header.epoch,
            height: header.height,
            block_hash,
            result,
            clock,
        };
        let mut retained = self.0.observations.lock();
        for slot in &mut retained.entries {
            if slot.is_some_and(|old| old.height != header.height) {
                *slot = None;
            }
            if slot.is_some_and(|old| {
                old.instance == observation.instance
                    && old.epoch == observation.epoch
                    && old.height == observation.height
                    && old.block_hash == observation.block_hash
                    && old.result == observation.result
            }) {
                // An execution retry must preserve its original parent policy and due facts.
                return;
            }
        }
        let index = retained.next;
        retained.entries[index] = Some(observation);
        retained.next = (index + 1) % OBSERVATIONS;
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the exact signed source tuple and independently authenticated certification state"
    )]
    fn authorize(
        &self,
        instance: Hash32,
        epoch: EpochId,
        height: u64,
        block_hash: Hash32,
        result: Hash32,
        certified: bool,
    ) -> Result<(), SigningError> {
        // This classification is made by the Core from its authenticated live PQC context,
        // including a certified re-proposal after restart. It never comes from this cache.
        if certified {
            return Ok(());
        }
        let observations = self
            .0
            .observations
            .try_lock()
            .ok_or(SigningError::Refused)?;
        let observed = observations
            .entries
            .iter()
            .flatten()
            .find(|value| {
                value.instance == instance
                    && value.epoch == epoch
                    && value.height == height
                    && value.block_hash == block_hash
                    && value.result == result
            })
            .ok_or(SigningError::Refused)?;
        if let Some(clock) = observed.clock {
            let wall_ms =
                u64::try_from(self.0.time.now().as_millis()).map_err(|_| SigningError::Refused)?;
            if !cfg!(all(test, sumeragi_core_mutation = "HC294"))
                && clock
                    .is_stale(wall_ms, false)
                    .map_err(|_| SigningError::Refused)?
            {
                return Err(SigningError::Refused);
            }
        }
        Ok(())
    }
}

/// The production native signer has no raw-Prepare path around original clock custody.
pub(crate) struct NativePrepareSigner {
    key: KeyPairSigner,
    clock: PrepareClock,
}

impl NativePrepareSigner {
    pub(crate) fn new(key: KeyPairSigner, clock: PrepareClock) -> Self {
        Self { key, clock }
    }
}

impl Signer for NativePrepareSigner {
    fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    fn sign_prepare(&self, context: &PrepareSigningContext<'_>) -> Result<Signature, SigningError> {
        self.clock.authorize(
            *context.instance(),
            *context.epoch(),
            context.height(),
            *context.block_hash(),
            *context.result(),
            context.certified(),
        )?;
        self.key.sign(context.preimage())
    }

    fn sign(&self, preimage: &[u8]) -> Result<Signature, SigningError> {
        let tag = iroha_sumeragi::preimage::TAG_SIG;
        if preimage.starts_with(tag)
            && preimage.get(tag.len()) == Some(&iroha_sumeragi::preimage::KIND_PREPARE)
        {
            return Err(SigningError::Refused);
        }
        self.key.sign(preimage)
    }
}

#[cfg(test)]
mod tests;
