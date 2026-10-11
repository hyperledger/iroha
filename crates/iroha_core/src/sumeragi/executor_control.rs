//! Serialized native control custody and exact transaction-quarantine provenance.

use super::*;
use crate::sumeragi::epoch_beacon::producer::{
    NativeBeaconError, NativeBeaconProducer, NativeBeaconReadiness, NativeBeaconReadinessError,
    NativeControlFailure,
};
use iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1;

pub(super) fn stopped() -> PublicationError {
    PublicationError::RecoveryRequired("executor thread stopped".into())
}

/// The core authenticates this exact header; pristine capture independently checks its source.
pub(super) fn pulse_context(
    header: &iroha_sumeragi::message::BlockHeader,
) -> GlobalThresholdBeaconPulseContextV1 {
    GlobalThresholdBeaconPulseContextV1 {
        instance: header.instance.0,
        epoch: header.epoch.epoch,
        epoch_context_id: header.epoch.context.0,
        parent_consensus_hash: header.parent_hash.0,
        parent_result: header.parent_result.0,
    }
}

/// Only a transaction-specific validation failure can authorize removing a queued transaction.
pub(super) fn transaction_rejection(error: &BlockValidationError) -> bool {
    matches!(
        error,
        BlockValidationError::TransactionAccept(_) | BlockValidationError::TransactionInTheFuture
    )
}

/// Keep the actual readiness admission through the serialized worker response.
fn readiness_failure(error: NativeBeaconReadinessError) -> PublicationError {
    if cfg!(all(test, sumeragi_core_mutation = "HC81")) {
        return PublicationError::Retryable(error.to_string());
    }
    match error {
        NativeBeaconReadinessError::Admission(original) => PublicationError::Deferred(
            crate::execution_attempt::ExecutionDeferred::from(original).into(),
        ),
        NativeBeaconReadinessError::Allocator(original) => PublicationError::Deferred(
            crate::sumeragi::driver::traits::PublicationDeferral::SharedControl(original),
        ),
        NativeBeaconReadinessError::AlreadyAttached => {
            PublicationError::RecoveryRequired(error.to_string())
        }
    }
}

impl Worker<'_> {
    pub(super) fn attach_beacon(
        &mut self,
        instance: Hash32,
        local_bls: Option<[u8; 48]>,
        signer: Option<Arc<dyn crate::beacon::GlobalThresholdBeaconPartialSignerV1>>,
    ) -> Result<NativeBeaconReadiness, PublicationError> {
        if self.beacon.is_some() {
            // Keep the original owner and all its partials. A second attach is never rotation.
            return Err(PublicationError::RecoveryRequired(
                "native beacon producer is already attached".into(),
            ));
        }
        if let Some(reason) = &self.recovery {
            return Err(PublicationError::RecoveryRequired(reason.clone()));
        }
        let mut producer = NativeBeaconProducer::new(instance, local_bls, signer);
        let reporting = producer
            .attach_readiness(&self.state.ivm_execution_budget())
            .map_err(readiness_failure)?;
        self.beacon = Some(producer);
        Ok(reporting)
    }

    fn control_available(&self) -> Result<(), PublicationError> {
        if let Some(reason) = &self.recovery {
            return Err(PublicationError::RecoveryRequired(reason.clone()));
        }
        if self.pending_commit.is_some() || self.publication_pending() {
            return Err(PublicationError::Retryable(
                "the original prepared publication is still retained".into(),
            ));
        }
        if self.beacon.is_none() {
            return Err(PublicationError::RecoveryRequired(
                "native beacon producer was not attached before driver start".into(),
            ));
        }
        Ok(())
    }

    fn control_error(
        &mut self,
        error: NativeBeaconError,
        class: NativeControlFailure,
    ) -> PublicationError {
        let reason = error.to_string();
        iroha_logger::debug!(
            %reason,
            ?class,
            applied_height = self.applied.0,
            applied_hash = ?self.applied.1,
            "native control retained its original source after refusal"
        );
        match class {
            NativeControlFailure::RecoveryRequired => {
                self.recovery = Some(reason.clone());
                PublicationError::RecoveryRequired(reason)
            }
            NativeControlFailure::Retryable | NativeControlFailure::Rejected => {
                PublicationError::Retryable(reason)
            }
        }
    }

    pub(super) fn build_control_witness(
        &mut self,
        context: &ControlWitnessContext,
    ) -> Result<ControlWitness, PublicationError> {
        self.control_available()?;
        self.beacon
            .as_ref()
            .expect("attached original producer")
            .build(context)
            .map_err(|error| {
                iroha_logger::debug!(?context, %error, "native control witness refused");
                let class = error.local_classification();
                self.control_error(error, class)
            })
    }

    pub(super) fn drive_control(
        &mut self,
        context: &ApplicationControlContext,
    ) -> Result<Option<ApplicationControl>, PublicationError> {
        self.control_available()?;
        let state = self.state;
        let generation = state.state_view_generation();
        let view = match state.try_view_once() {
            Ok(view) => view,
            Err(error) => {
                let error = PublicationError::from(error);
                if let PublicationError::RecoveryRequired(reason) = &error {
                    self.recovery = Some(reason.clone());
                }
                return Err(error);
            }
        };
        let observed = self
            .beacon
            .as_ref()
            .expect("attached original producer")
            .refresh_readiness(&view, context, self.applied, generation);
        if let Err(error) = observed {
            iroha_logger::debug!(?context, %error, "native control parent observation refused");
            let class = error.local_classification();
            return Err(self.control_error(error, class));
        }
        let produced = self
            .beacon
            .as_mut()
            .expect("attached original producer")
            .drive(&view, context, self.applied);
        match produced {
            Ok(bytes) => Ok(bytes.map(|bytes| ApplicationControl {
                context: *context,
                bytes,
            })),
            Err(error) => {
                iroha_logger::debug!(?context, %error, "native control source drive refused");
                let class = error.local_classification();
                Err(self.control_error(error, class))
            }
        }
    }

    pub(super) fn receive_application_control(
        &mut self,
        from: &PublicKey,
        message: &ApplicationControl,
    ) -> Result<(), PublicationError> {
        self.control_available()?;
        let state = self.state;
        let view = match state.try_view_once() {
            Ok(view) => view,
            Err(error) => {
                let error = PublicationError::from(error);
                if let PublicationError::RecoveryRequired(reason) = &error {
                    self.recovery = Some(reason.clone());
                }
                return Err(error);
            }
        };
        let accepted = self
            .beacon
            .as_mut()
            .expect("attached original producer")
            .accept(&view, self.applied, from, message);
        match accepted {
            Ok(_) => Ok(()),
            Err(error) => {
                let class = error.ingress_classification();
                if class == NativeControlFailure::Rejected {
                    // An authenticated peer can still send bad or stale data. Discard only
                    // that frame; never turn it into a local retry, halt or queue removal.
                    return Ok(());
                }
                Err(self.control_error(error, class))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi::driver::traits::PublicationDeferral;
    use iroha_allocation::{AllocationBudget, ChargedShared, PrepaidSharedError};

    #[test]
    fn control_and_local_source_failures_never_authorize_transaction_quarantine() {
        for error in [
            BlockValidationError::ExecutionContextInvalid("missing or invalid pulse".into()),
            BlockValidationError::NposEffectsInvalid("wrong generation".into()),
            BlockValidationError::LocalStorageRecoveryRequired {
                reason: "committed parent is absent".into(),
            },
            BlockValidationError::DuplicateTransactions,
            BlockValidationError::MerkleRootMismatch,
        ] {
            assert!(!transaction_rejection(&error));
        }
        assert!(transaction_rejection(
            &BlockValidationError::TransactionInTheFuture
        ));
    }
    #[test]
    fn readiness_allocator_failure_retains_concrete_non_source_error() {
        let budget = AllocationBudget::new(0);
        let mut reservation = budget.try_reserve_bytes(0).unwrap();
        let (original, error) = ChargedShared::from_reservation(17u8, &mut reservation)
            .expect_err("an empty reservation cannot construct the physical control");
        assert_eq!(original, 17);
        assert!(matches!(error, PrepaidSharedError::Reservation(_)));
        let failure = readiness_failure(NativeBeaconReadinessError::Allocator(error));
        let PublicationError::Deferred(ref retained) = failure else {
            panic!("retain the concrete allocator failure, got {failure:?}");
        };
        assert_eq!(retained, &PublicationDeferral::SharedControl(error));
        assert!(retained.allocation_refusal().is_none());
        assert!(retained.release_wait().is_none());
        assert!(retained.execution().is_none());
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
