//! Native lane frame custody retains the original prepaid selected configuration.
//!
//! This reader shares the canonical file decoder and the exact QC/RS16 verifiers. The
//! caller chooses a hash beneath an independently authenticated global frontier. Header/QC
//! metadata and BLS caches remain separate resource-accounting obligations.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use std::{borrow::Borrow, io, path::PathBuf};

use iroha_allocation::{AllocationBudget, RetainedPayload};
use iroha_sumeragi::{
    availability::{AvailabilitySource, AvailableBody, BodyRestoration},
    crypto::{Crypto, Verifier},
    message::{BlockHeader, Qc},
    types::{Hash32, HeightConfig},
};

use crate::sumeragi::lanes::{
    record::LaneRecord,
    store::read::{ReadRecord, RecordPoll},
};

/// Move-only original configuration; no public extraction or metadata clone detaches its ledger.
pub(in crate::sumeragi) struct FundedLaneSource(RetainedPayload<AvailabilitySource>);
impl Borrow<AvailabilitySource> for FundedLaneSource {
    fn borrow(&self) -> &AvailabilitySource {
        self.0.get()
    }
}
impl FundedLaneSource {
    #[expect(
        unsafe_code,
        reason = "only move the same prepaid config fields into a scalar source wrapper"
    )]
    pub(in crate::sumeragi) fn new(
        config: RetainedPayload<HeightConfig>,
        instance: Hash32,
        height: u64,
        hash: Hash32,
        budget: &AllocationBudget,
    ) -> Result<Self, (RetainedPayload<HeightConfig>, io::Error)> {
        if !config.belongs_to(budget) || !config.get().epoch.contains(height) {
            return Err((
                config,
                std::io::Error::from(std::io::ErrorKind::InvalidInput).into(),
            ));
        }
        // SAFETY: AvailabilitySource adds only fixed scalar identity. Its private config is
        // exactly the moved original config; no allocation is cloned, exported or replaced.
        // Source and restoration expose only shared borrows, and FundedLaneSource is not Clone.
        let source = unsafe {
            config.map_payload(|config| {
                AvailabilitySource::new(instance, height, hash, config)
                    .expect("the exact original epoch bound was checked above")
            })
        };
        Ok(Self(source))
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget)
    }
}

pub(in crate::sumeragi) struct FundedLaneBody {
    pub(in crate::sumeragi) body: AvailableBody<FundedLaneSource>,
    pub(in crate::sumeragi) qc: Qc,
}
impl Borrow<BlockHeader> for FundedLaneBody {
    fn borrow(&self) -> &BlockHeader {
        self.body.header()
    }
}

enum Stage {
    Unopened,
    Reading(ReadRecord),
    Decoded(LaneRecord),
    Restoring(BodyRestoration<FundedLaneSource>, Qc),
    Consumed,
}
/// A read never substitutes its path, source, configuration, or original finite pool on retry.
pub(in crate::sumeragi) struct FundedLaneFrameRead {
    path: PathBuf,
    budget: AllocationBudget,
    source: Option<FundedLaneSource>,
    stage: Stage,
}
impl FundedLaneFrameRead {
    pub(in crate::sumeragi) fn new(
        path: PathBuf,
        source: FundedLaneSource,
        budget: AllocationBudget,
    ) -> Self {
        Self {
            path,
            source: Some(source),
            budget,
            stage: Stage::Unopened,
        }
    }
    pub(in crate::sumeragi) fn poll(
        &mut self,
        budget: &AllocationBudget,
        crypto: &dyn Crypto,
    ) -> Result<FundedLaneBody, Attempt<io::Error>> {
        if !self.budget.same_pool(budget)
            || self
                .source
                .as_ref()
                .is_some_and(|source| !source.belongs_to(budget))
        {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into());
        }
        // A stricter caller-owned Norito scope is not a fact about the durable frame.
        // Keep the same read owner for retry after that scope ends; intrinsic canonical
        // limits without an outer scope still report invalid storage material.

        loop {
            match std::mem::replace(&mut self.stage, Stage::Consumed) {
                Stage::Unopened => match ReadRecord::open(&self.path, budget.clone()) {
                    Ok(read) => self.stage = Stage::Reading(read),
                    Err(error) => {
                        self.stage = Stage::Unopened;
                        return Err(error.into());
                    }
                },
                Stage::Reading(mut read) => match read.poll(budget) {
                    Ok(RecordPoll::Ready(record)) => self.stage = Stage::Decoded(record),
                    outcome => {
                        self.stage = Stage::Reading(read);
                        return Err(match outcome {
                            Ok(RecordPoll::Absent) => {
                                std::io::Error::from(std::io::ErrorKind::NotFound).into()
                            }
                            Ok(RecordPoll::Pending(error)) => {
                                crate::sumeragi::storage_attempt::byte(error)
                            }
                            Err(error) => error.into_attempt(),
                            Ok(RecordPoll::Ready(_)) => unreachable!(),
                        });
                    }
                },
                Stage::Decoded(record) => {
                    let source = self
                        .source
                        .as_ref()
                        .expect("source remains before restoration");
                    let expected = source.borrow();
                    let header = record.header();
                    let valid = record.check_context(expected, crypto).is_ok()
                        && header.control_witness.is_empty()
                        && Verifier::new(
                            crypto,
                            &expected.instance(),
                            &expected.config().epoch.id,
                            &expected.config().committee,
                        )
                        .verify_commit_qc(record.commit_qc(), Some(header));
                    if !valid {
                        self.stage = Stage::Decoded(record);
                        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into());
                    }
                    let source = self
                        .source
                        .take()
                        .expect("same original owner checked above");
                    let (restoration, qc) = record.into_restoration(source);
                    self.stage = Stage::Restoring(restoration, qc);
                }
                Stage::Restoring(restoration, qc) => match restoration.complete(budget, crypto) {
                    Ok(body) => return Ok(FundedLaneBody { body, qc }),
                    Err((restoration, error)) => {
                        self.stage = Stage::Restoring(restoration, qc);
                        return Err(crate::sumeragi::storage_attempt::restoration(error));
                    }
                },
                Stage::Consumed => {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
