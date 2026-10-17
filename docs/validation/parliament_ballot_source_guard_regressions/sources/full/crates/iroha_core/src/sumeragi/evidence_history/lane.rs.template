//! Retained complete native parent/demotion custody under one original global admission cut.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::runtime_availability::history::payload_error;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_sumeragi::{
    api::CommittedTip,
    evidence::{EvidenceContext, verify_evidence},
    message::Evidence,
    types::Hash32,
};
use std::io;

use crate::sumeragi::lanes::evidence::frame::{
    FundedLaneBody, FundedLaneFrameRead, FundedLaneSource,
};
use crate::{
    query::native_receipts::lane_payload::{LaneAuthority, LanePayload, LanePayloadError},
    sumeragi::{
        crypto::BlsCrypto, lanes::evidence::LaneAncestry,
        runtime_availability::history::LaneEvidenceContext,
    },
};

/// Existing selected source and complete demotion bodies survive every local refusal.
pub(super) struct LaneProofRead {
    cursor: LaneAncestry<LaneAuthority>,
    payload: LanePayload,
    scope: iroha_data_model::block::consensus::LaneEvidenceScope,
    tip: crate::state::NativeExecutionTip,
    instance: Hash32,
    kura: std::sync::Arc<crate::kura::Kura>,
    budget: AllocationBudget,
    crypto: BlsCrypto,
    headers: ChargedBuffer<FundedLaneBody>,
    frame: Option<FundedLaneFrameRead>,
    ready: Option<FundedLaneBody>,
    parent: Option<CommittedTip>,
    ordered: bool,
}
impl LaneProofRead {
    pub(super) fn new(
        context: LaneEvidenceContext,
        height: u64,
    ) -> Result<Self, (LaneEvidenceContext, Attempt<io::Error>)> {
        let frontier = match context.payload.custody_record(&context.scope.incarnation) {
            Ok(Some(row)) => row.frontier(),
            Ok(None) => {
                return Err((
                    context,
                    std::io::Error::from(std::io::ErrorKind::InvalidData).into(),
                ));
            }
            Err(error) => return Err((context, payload_error(error))),
        };
        let genesis = context.authority.genesis();
        let window = context.authority.demotion_window();
        let interval = iroha_sumeragi::topology::demotion_window(height, 0, window);
        let count = interval
            .map_or(Some(0), |(first, last)| {
                last.checked_sub(first).and_then(|n| n.checked_add(1))
            })
            .and_then(|count| usize::try_from(count).ok());
        let Some(count) = count else {
            return Err((
                context,
                std::io::Error::from(std::io::ErrorKind::InvalidData).into(),
            ));
        };
        let headers = match ChargedBuffer::new(count, &context.budget) {
            Ok(headers) => headers,
            Err(error) => {
                return Err((
                    context,
                    payload_error(LanePayloadError::Materialization(
                        iroha_allocation::PrepaidBufferError::Allocation(error),
                    )),
                ));
            }
        };
        let crypto = BlsCrypto::new();
        if let Err(error) = context.authority.visit_members(|key, proof| {
            let key = iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::BlsNormal, key)
                .map_err(|_| {
                    crate::query::native_receipts::lane_payload::LanePayloadError::Source
                })?;
            crypto.admit(&key, proof).map_err(|_| {
                crate::query::native_receipts::lane_payload::LanePayloadError::Source
            })?;
            Ok(())
        }) {
            return Err((context, payload_error(error)));
        }
        let LaneEvidenceContext {
            authority,
            payload,
            scope,
            instance,
            original_tip: tip,
            generation,
            network,
            budget,
            kura,
        } = context;
        let cursor = match LaneAncestry::new(instance, authority, genesis, frontier, height, window)
        {
            Ok(cursor) => cursor,
            Err((authority, error)) => {
                return Err((
                    LaneEvidenceContext {
                        authority,
                        payload,
                        scope,
                        instance,
                        original_tip: tip,
                        generation,
                        network,
                        budget,
                        kura,
                    },
                    io::Error::new(io::ErrorKind::InvalidData, error).into(),
                ));
            }
        };
        let parent = (cursor.parent_height() == 0).then_some(CommittedTip {
            height: 0,
            block_hash: Hash32(genesis.block_hash),
            result: Hash32(genesis.result),
            header: None,
            commit_qc: None,
        });
        Ok(Self {
            cursor,
            payload,
            scope,
            tip,
            instance,
            kura,
            budget,
            crypto,
            headers,
            frame: None,
            ready: None,
            parent,
            ordered: false,
        })
    }
    pub(super) fn poll(&mut self) -> Result<(), Attempt<io::Error>> {
        while let Some(expected) = self.cursor.next_frontier() {
            if self.frame.is_none() {
                let config = self
                    .cursor
                    .configuration_owner()
                    .copy_config(&self.budget)
                    .map_err(payload_error)?;
                let source = FundedLaneSource::new(
                    config,
                    self.instance,
                    expected.height,
                    Hash32(expected.block_hash),
                    &self.budget,
                )
                .map_err(|(_, error)| error)?;
                let path = self
                    .kura
                    .store_root()
                    .join("lanes")
                    .join(hex::encode(self.instance.0))
                    .join(format!("{:020}.frame", expected.height));
                self.frame = Some(FundedLaneFrameRead::new(path, source, self.budget.clone()));
            }
            if self.ready.is_none() {
                self.ready = Some(
                    self.frame
                        .as_mut()
                        .expect("same pending original frame")
                        .poll(&self.budget, &self.crypto)?,
                );
            }
            let retain = self
                .cursor
                .demotion_interval()
                .is_some_and(|(first, last)| first <= expected.height && expected.height <= last);
            if retain && self.headers.as_slice().len() == self.headers.capacity() {
                // Preserve both the cursor and the actual original frame on an inconsistent
                // descriptor bound. An impossible push must never discard native custody.
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into());
            }
            let original = self.ready.as_ref().expect("original complete body custody");
            // Every frame above the interval is authenticated too; a file QC cannot select a branch.
            self.cursor
                .advance(&self.crypto, &original.body, &original.qc)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            self.frame = None;
            let original = self.ready.take().expect("validated same original frame");
            if expected.height == self.cursor.parent_height() {
                self.parent = Some(CommittedTip {
                    height: expected.height,
                    block_hash: Hash32(expected.block_hash),
                    result: Hash32(expected.result),
                    header: None,
                    commit_qc: None,
                });
            }
            if retain && let Err(original) = self.headers.try_push(original) {
                self.ready = Some(original);
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into());
            }
        }
        if self.headers.as_slice().len() != self.headers.capacity() {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into());
        }
        if !self.ordered {
            self.headers.as_mut_slice().reverse();
            self.ordered = true;
        }
        Ok(())
    }
    pub(super) fn verify(
        &self,
        evidence: &Evidence,
    ) -> Result<super::VerifiedNativeEvidence, super::NativeEvidenceError> {
        let (_, height, _) = super::subject(evidence);
        let parent = self.parent.as_ref().ok_or_else(|| {
            super::NativeEvidenceError::Context("original native parent is incomplete".into())
        })?;
        if self.cursor.next_height().is_some() || !self.ordered {
            return Err(super::NativeEvidenceError::Context(
                "complete native demotion custody is unavailable".into(),
            ));
        }
        let config = self.cursor.config();
        let context = EvidenceContext {
            instance: self.instance,
            height,
            config,
            genesis_height: 0,
            parent,
            parent_config: (parent.height > 0).then_some(config),
            demotion_window: self.cursor.configuration_owner().demotion_window(),
            demotion_headers: self.headers.as_slice(),
        };
        let attribution = verify_evidence(&self.crypto, &context, evidence)?;
        let row = self
            .payload
            .custody_record(&self.scope.incarnation)
            .map_err(|error| super::NativeEvidenceError::Source(payload_error(error)))?
            .ok_or_else(|| {
                super::NativeEvidenceError::Context("original custody disappeared".into())
            })?;
        let offenders = super::funded_attribution::FundedOffenders::collect(
            attribution.offenders().ones().count(),
            attribution.offenders().ones(),
            &self.budget,
            |signer, budget| {
                let key = config
                    .committee
                    .members()
                    .get(signer as usize)
                    .ok_or_else(|| {
                        super::NativeEvidenceError::Context(
                            "verified native signer is outside its pinned committee".into(),
                        )
                    })?;
                let peer_key = iroha_crypto::PreparedPublicKeyDecode::try_from_material(
                    iroha_crypto::Algorithm::BlsNormal,
                    key.as_bytes(),
                    budget,
                )
                .map_err(|error| match error {
                    iroha_crypto::PublicKeyDecodeAdmissionError::Allocation(error) => {
                        super::NativeEvidenceError::Preparation(
                            crate::state::EvidencePreparationError::from(error),
                        )
                    }
                    iroha_crypto::PublicKeyDecodeAdmissionError::Codec(error) => {
                        super::NativeEvidenceError::Context(error.to_string())
                    }
                })?;
                let lane_stake = row.binding(signer).map_err(|error| {
                    super::NativeEvidenceError::Source(payload_error(error.into()))
                })?;
                Ok((peer_key, lane_stake))
            },
        )?;
        Ok(super::VerifiedNativeEvidence {
            scope: iroha_data_model::block::consensus::EvidenceScope::Lane(self.scope),
            tip: self.tip,
            instance: self.instance,
            epoch: config.epoch.id,
            authority_generation: config.epoch.authority_generation,
            height,
            offenders,
            safety_violation: attribution.safety_violation(),
        })
    }
}

#[cfg(test)]
mod tests;
