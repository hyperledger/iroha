//! Exact source-owned reputation delivery under the original gateway operation deadline.
use super::*;
use iroha_core::query::stream_token_gateway::observation::begin_stream_token_reputation_delivery_v1;
use iroha_data_model::{
    sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryDispositionV1 as Disposition,
    transaction::SignedTransaction,
};

/// One publication-leased decision; terminal outcomes never carry a signing recipe.
enum DeliveryStep {
    Closed,
    Append(Box<SignedTransaction>),
    CheckExpiry,
}

impl NativeGateway {
    fn delivery_step(
        &self,
        original: &Record,
        deadline: Instant,
        may_submit: bool,
    ) -> Result<DeliveryStep, Error> {
        self.check_deadline(deadline)?;
        let prepared = begin_stream_token_reputation_delivery_v1(
            self.state.clone(),
            *self.state.network_id_ref(),
            self.qualification,
            self.transactions.operator().clone(),
            self.transactions.observer().clone(),
            *original,
            deadline,
        )
        .map_err(observation_error)?;
        let signed = self
            .transactions
            .sign(prepared.instruction(), true, deadline)?;
        let pending =
            complete_binding(prepared.bind_signed_transaction(signed)).map_err(binding_error)?;
        self.transactions
            .submit_and_wait(pending.signed_transaction(), pending.deadline())?;
        let proof = complete_check(pending.verify_finalized(|| self.time()), |failure| {
            failure.into_pending().verify_finalized(|| self.time())
        })
        .map_err(verification_error)?;
        // A failed source recheck returns before this callback runs. A retry re-verifies the
        // same signed Check; signing the Append is entered once, only after the final fence.
        let consume = |proof: Verified| {
            proof.consume_for_reputation_delivery(
                original,
                || self.time(),
                |delivery| match delivery.disposition() {
                    Disposition::Delivered { .. }
                    | Disposition::Excluded
                    | Disposition::Expired { .. }
                    | Disposition::GovernanceCancelled { .. } => Ok(DeliveryStep::Closed),
                    Disposition::Pending if !may_submit => Err(Error::Ambiguous),
                    Disposition::Pending if delivery.needs_terminal_check() => {
                        Ok(DeliveryStep::CheckExpiry)
                    }
                    Disposition::Pending => self
                        .transactions
                        .sign_reputation_delivery(&delivery, deadline)
                        .map(Box::new)
                        .map(DeliveryStep::Append),
                },
            )
        };
        let step = complete_check(consume(proof), |failure| {
            consume(failure.into_pending().verify_finalized(|| self.time())?)
        })
        .map_err(verification_error)??;
        self.check_deadline(deadline)?;
        Ok(step)
    }
}

impl StreamTokenReputationDeliveryV1 for NativeGateway {
    fn configured_qualification(&self) -> Qualification {
        self.qualification
    }
    fn deliver(&self, record: &Record, deadline: Instant) -> Result<(), Error> {
        let step = self.delivery_step(record, deadline, true)?;
        let submitted = match step {
            DeliveryStep::Closed => return self.check_deadline(deadline),
            DeliveryStep::Append(signed) => self
                .transactions
                .submit_and_wait(&signed, deadline)
                .map(|_| ()),
            // Eligibility is not expiry authority. Ack must make the actual consensus decision;
            // the independent subsequent Check must prove its permanent terminal disposition.
            DeliveryStep::CheckExpiry => self.acknowledge(record, deadline).map(|_| ()),
        };
        // Even an ambiguous queue result may have committed. Recover only this original source;
        // never sign or submit another Append during this call, and never renew its deadline.
        match self.delivery_step(record, deadline, false) {
            Ok(DeliveryStep::Closed) => self.check_deadline(deadline),
            Ok(_) => Err(Error::Ambiguous),
            Err(error) => Err(submitted.err().unwrap_or(error)),
        }
    }
}
