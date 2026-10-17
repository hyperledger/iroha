//! Original native proposal timestamp admission across authoring and restart waits.

use super::*;
use crate::sumeragi::proposal_admission::{self, ProposalSource};
use iroha_sumeragi::proposal_admission::{BuiltPayload, ProposalAdmission};

/// Original restart body, paid decode progress and one captured publication owner.
pub(super) struct ProposalRecovery {
    pub(super) source: AvailableBody,
    pub(super) block_hash: Hash32,
    pub(super) decode: Option<SignatureDecodeAttempt>,
    admission: Option<ProposalAdmission>,
}

impl ProposalRecovery {
    /// Move the paid graph into ordinary execution while retaining its signing admission.
    /// Incomplete recovery and mismatched candidates keep their original decoder.
    pub(super) fn take_execution_decode(
        &mut self,
        body: &AvailableBody,
        block_hash: Hash32,
    ) -> Option<SignatureDecodeAttempt> {
        if self.admission.is_some() && self.block_hash == block_hash && self.source == *body {
            self.decode.take()
        } else {
            None
        }
    }
}

impl Worker<'_> {
    pub(super) fn admit_built_payload(
        &mut self,
        payload: PayloadBytes,
        height: u64,
        view_number: u64,
    ) -> Result<BuiltPayload, PublicationError> {
        let (scope, time, original_admission) =
            if let Some(original) = self.completed_payload.as_ref() {
                (
                    original.scope,
                    original.creation_time,
                    original.proposal_admission.clone(),
                )
            } else if let Some(original) = self.payload_build.as_ref() {
                (
                    original.scope,
                    original.job.source().block.header().creation_time(),
                    original.proposal_admission.clone(),
                )
            } else {
                // Queue expiry or withdrawal during encoding retires this source.
                // It cannot authorize publication, but ordinary churn is not a fault.
                let reason = "completed proposal input custody retired before admission".into();
                return Err(if cfg!(all(test, sumeragi_core_mutation = "HC380")) {
                    PublicationError::RecoveryRequired(reason)
                } else {
                    PublicationError::Retryable(reason)
                });
            };
        let view = self.state.try_view_once().map_err(PublicationError::from)?;
        if scope.height != height
            || scope.view != view_number
            || !scope.is_current(self.state, &view, self.applied)
        {
            return Err(PublicationError::Retryable(
                "completed proposal parent changed before admission".into(),
            ));
        }
        if let Some(admission) = original_admission {
            return Ok(BuiltPayload { payload, admission });
        }
        let parent = scope.parent.ok_or_else(|| {
            PublicationError::RecoveryRequired(
                "completed proposal has no authenticated parent".into(),
            )
        })?;
        let instance = crate::sumeragi::certified_chain::CertifiedChain::new(&view)
            .map_err(|error| error.map_rejection(|error| error.to_string()))?
            .instance();
        let scheduled = view
            .world()
            .consensus_schedule()
            .ready(height)
            .map_err(|error| PublicationError::RecoveryRequired(error.to_string()))?;
        let epoch = schedule::core_epoch(&scheduled.epoch)
            .map_err(|error| PublicationError::RecoveryRequired(error.to_string()))?
            .id;
        let admission = proposal_admission::capture(
            ProposalSource {
                instance,
                epoch,
                height,
                view: view_number,
                parent_hash: parent.core_hash(),
                parent_result: parent.result(),
                block_hash: None,
            },
            &payload,
            time,
            &self.context.time_source,
            &self.state.ivm_execution_budget(),
        )?;
        drop(view);
        if let Some(original) = self.completed_payload.as_mut() {
            original.proposal_admission = Some(admission.clone());
        } else if let Some(original) = self.payload_build.as_mut() {
            original.proposal_admission = Some(admission.clone());
        }
        Ok(BuiltPayload { payload, admission })
    }

    pub(super) fn recover_proposal_admission(
        &mut self,
        body: &AvailableBody,
    ) -> Result<ProposalAdmission, PublicationError> {
        let budget = self.state.ivm_execution_budget();
        require_body_admission(body, &budget)?;
        let crypto = self.context.crypto.as_ref().ok_or_else(|| {
            PublicationError::RecoveryRequired("native proposal crypto is unavailable".into())
        })?;
        let block_hash = body.hash(&**crypto);
        let view = self.state.try_view_once().map_err(PublicationError::from)?;
        let parent = view.native_execution_tip().ok_or_else(|| {
            PublicationError::Retryable("proposal recovery awaits its applied parent".into())
        })?;
        let header = body.header();
        if parent.height().checked_add(1) != Some(header.height)
            || parent.core_hash() != header.parent_hash
            || parent.result() != header.parent_result
        {
            return Err(PublicationError::Retryable(
                "proposal recovery awaits its exact original parent".into(),
            ));
        }
        let instance = crate::sumeragi::certified_chain::CertifiedChain::new(&view)
            .map_err(|error| error.map_rejection(|error| error.to_string()))?
            .instance();
        let config = view
            .world()
            .consensus_schedule()
            .ready(header.height)
            .map_err(|error| PublicationError::RecoveryRequired(error.to_string()))?
            .height_config()
            .map_err(|error| PublicationError::RecoveryRequired(error.to_string()))?;
        if body.source().instance() != instance || body.source().config() != &config {
            return Err(PublicationError::RecoveryRequired(
                "proposal recovery changed original scheduled authority".into(),
            ));
        }
        drop(view);
        if self
            .proposal_decode
            .as_ref()
            .is_some_and(|original| original.source != *body)
        {
            self.proposal_decode = None;
        }
        if self.proposal_decode.is_none() {
            let decoder =
                iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&budget)
                    .map_err(|error| {
                        match crate::execution_attempt::prepared_signature_block_attempt_error(
                            error,
                            |reason| reason,
                        ) {
                            crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                                PublicationError::Deferred(original.into())
                            }
                            crate::execution_attempt::ExecutionAttemptError::Rejected(reason) => {
                                PublicationError::RecoveryRequired(reason)
                            }
                        }
                    })?;
            self.proposal_decode = Some(ProposalRecovery {
                source: body.clone(),
                block_hash,
                decode: Some(SignatureDecodeAttempt {
                    block_hash,
                    source: body.clone(),
                    decoder,
                    decoded: None,
                    returned_refusal: None,
                    amx_legs: None,
                    parent_service:
                        super::super::certified_chain::ParentServicePreparation::default(),
                }),
                admission: None,
            });
        }
        let original = self
            .proposal_decode
            .as_mut()
            .expect("original recovery decode retained");
        if let Some(admission) = original.admission.as_ref() {
            return Ok(admission.clone());
        }
        let decoded = original
            .decode
            .as_mut()
            .expect("unadmitted recovery retains its original decoder")
            .original_decoded(&budget)
            .map_err(|error| match error {
                payload::PayloadError::DecodeResource(original) => {
                    PublicationError::Deferred(original.into())
                }
                error => PublicationError::RecoveryRequired(error.to_string()),
            })?;
        if decoded.header().height().get() != header.height
            || decoded.header().view_change_index() != header.origin_view
        {
            return Err(PublicationError::RecoveryRequired(
                "proposal payload changed original header coordinates".into(),
            ));
        }
        let admission = proposal_admission::capture(
            ProposalSource {
                instance,
                epoch: header.epoch,
                height: header.height,
                view: header.origin_view,
                parent_hash: header.parent_hash,
                parent_result: header.parent_result,
                block_hash: Some(block_hash),
            },
            body.payload(),
            decoded.header().creation_time(),
            &self.context.time_source,
            &budget,
        )?;
        original.admission = Some(admission.clone());
        Ok(admission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_sumeragi::{crypto::SigningError, testing::proposal_signing_request};

    #[test]
    fn recovery_decode_handoff_retains_refusals_and_requires_exact_source() {
        publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let body = publication_tests::proposal(chain, worker);
            let other =
                publication_tests::proposal_with_transaction(chain, worker, |chain, time| {
                    chain.tick(time.checked_sub(1).unwrap())
                });
            assert_ne!(body, other);
            let hash = body.hash(&**worker.context.crypto.as_ref().unwrap());
            assert_ne!(hash, Hash32::ZERO);
            let budget = worker.state.ivm_execution_budget();
            let mut decode = SignatureDecodeAttempt {
                block_hash: hash,
                source: body.clone(),
                decoder: iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&budget)
                    .unwrap(),
                decoded: None,
                returned_refusal: None,
                amx_legs: None,
                parent_service:
                    super::super::super::certified_chain::ParentServicePreparation::default(),
            };
            // Refuse inside this original decoder, rather than an earlier genesis
            // authentication performed by the ordinary recovery entry point.
            norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 64),
                || {
                    assert!(matches!(
                        decode.original_decoded(&budget),
                        Err(payload::PayloadError::DecodeResource(_))
                    ));
                },
            );
            worker.proposal_decode = Some(ProposalRecovery {
                source: body.clone(),
                block_hash: hash,
                decode: Some(decode),
                admission: None,
            });
            let original = worker.proposal_decode.as_mut().unwrap();
            let retained = std::ptr::from_ref(original.decode.as_ref().unwrap());
            assert!(original.take_execution_decode(&body, hash).is_none());
            assert_eq!(
                std::ptr::from_ref(original.decode.as_ref().unwrap()),
                retained,
                "a deferred recovery keeps its original decode progress"
            );

            let admission = worker.recover_proposal_admission(&body).unwrap();
            let original = worker.proposal_decode.as_mut().unwrap();
            assert!(
                original
                    .take_execution_decode(&body, Hash32::ZERO)
                    .is_none()
            );
            assert!(original.take_execution_decode(&other, hash).is_none());
            assert_eq!(
                std::ptr::from_ref(original.decode.as_ref().unwrap()),
                retained,
                "a mismatched candidate cannot take the original graph"
            );
            assert_eq!(worker.recover_proposal_admission(&body).unwrap(), admission);
        });
    }

    #[test]
    fn execution_reuses_recovered_proposal_decode_and_keeps_signing_admission() {
        publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let body = publication_tests::proposal(chain, worker);
            let hash = body.hash(&**worker.context.crypto.as_ref().unwrap());
            let admission = worker.recover_proposal_admission(&body).unwrap();
            let original = worker
                .proposal_decode
                .as_ref()
                .unwrap()
                .decode
                .as_ref()
                .unwrap()
                .decoded
                .as_ref()
                .unwrap();
            assert!(!original.external_entrypoints_slice().is_empty());
            let entries = original.external_entrypoints_slice().as_ptr();
            let request = proposal_signing_request(
                &body,
                hash,
                body.header().origin_view,
                Hash32::ZERO,
                false,
            );
            assert_eq!(admission.check(&request), Ok(()));

            assert!(matches!(
                worker.execute(&body, hash, false),
                Ok(Some(ExecOutcome::Valid { .. }))
            ));
            let PublicationPhase::Executed { valid, .. } = &worker.live.as_ref().unwrap().phase
            else {
                panic!("the recovered original must complete ordinary validation");
            };
            assert_eq!(
                valid.as_ref().external_entrypoints_slice().as_ptr(),
                entries,
                "execution must consume the paid recovery graph, not decode another copy"
            );

            // Execution owns the graph now; a signing retry must still borrow the
            // original admission without allocating or reconstructing that graph.
            let epoch = crossbeam_epoch::pin();
            let budget = worker.state.ivm_execution_budget();
            let occupied = budget.reserved_bytes();
            let retry = worker.recover_proposal_admission(&body).unwrap();
            assert_eq!(retry, admission);
            assert_eq!(retry.check(&request), Ok(()));
            assert_eq!(budget.reserved_bytes(), occupied);
            assert_eq!(worker.state.view().height(), 1);
            drop(epoch);
        });
    }

    #[test]
    fn native_original_proposal_rechecks_clock_after_worker_wait_and_restart() {
        let (clock, time_source) =
            iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(20_000));
        publication_tests::with_worker_clock(
            time_source,
            move |chain, worker, _blocks, _events| {
                let body = publication_tests::proposal(chain, worker);
                let hash = body.hash(&**worker.context.crypto.as_ref().unwrap());
                let original_time = payload::decode(body.payload().as_slice())
                    .unwrap()
                    .header()
                    .creation_time();
                let admission = worker.recover_proposal_admission(&body).unwrap();
                let request = proposal_signing_request(
                    &body,
                    hash,
                    body.header().origin_view,
                    Hash32::ZERO,
                    false,
                );
                clock.set(
                    original_time
                        .checked_sub(Duration::from_millis(1))
                        .expect("original proposal time exceeds one millisecond"),
                );
                assert!(
                    matches!(
                        admission.check(&request),
                        Err(SigningError::ClockAhead {
                            max_clock_drift_ms: 0,
                            ..
                        })
                    ),
                    "native first proposal must recheck the clock after original worker custody"
                );
                let decoded = std::ptr::from_ref(
                    worker
                        .proposal_decode
                        .as_ref()
                        .unwrap()
                        .decode
                        .as_ref()
                        .unwrap()
                        .decoded
                        .as_ref()
                        .unwrap(),
                );
                let retry = worker.recover_proposal_admission(&body).unwrap();
                assert_eq!(
                    admission, retry,
                    "recovery must retain the original paid admission owner"
                );
                assert_eq!(
                    std::ptr::from_ref(
                        worker
                            .proposal_decode
                            .as_ref()
                            .unwrap()
                            .decode
                            .as_ref()
                            .unwrap()
                            .decoded
                            .as_ref()
                            .unwrap()
                    ),
                    decoded
                );
                assert!(matches!(
                    retry.check(&request),
                    Err(SigningError::ClockAhead { .. })
                ));
                let certified = proposal_signing_request(
                    &body,
                    hash,
                    body.header().origin_view,
                    Hash32::ZERO,
                    true,
                );
                assert_eq!(admission.check(&certified), Ok(()));
                let changed = proposal_signing_request(
                    &body,
                    hash,
                    body.header().origin_view + 1,
                    Hash32::ZERO,
                    true,
                );
                assert_eq!(admission.check(&changed), Err(SigningError::InvalidInput));
                clock.set(original_time);
                assert_eq!(admission.check(&request), Ok(()));
                assert_eq!(retry.check(&request), Ok(()));
                assert_eq!(body.hash(&**worker.context.crypto.as_ref().unwrap()), hash);
            },
        );
    }
}
