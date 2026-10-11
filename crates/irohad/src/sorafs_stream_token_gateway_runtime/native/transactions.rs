//! Exact-envelope native queue submission under the caller's original absolute deadline.
use super::*;
use crate::runtime_credential::load_bounded_runtime_credential_v1;
use iroha_core::{state::StateReadOnly, tx::AcceptedTransaction};
use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair, PublicKey};
use iroha_data_model::transaction::{
    FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionEntrypoint,
};
use std::path::Path;
use zeroize::Zeroizing;

pub(super) struct NativeTransactions {
    state: Arc<State>,
    queue: Arc<Queue>,
    qualification: Qualification,
    operator: AccountId,
    operator_key: KeyPair,
    observer: AccountId,
    observer_key: KeyPair,
    reputation_recorder: AccountId,
    reputation_recorder_key: KeyPair,
    fee_payment: FeePaymentIntent,
    #[cfg(test)]
    pub(super) sign_calls: std::sync::atomic::AtomicUsize,
}
impl NativeTransactions {
    pub(super) fn new(
        state: Arc<State>,
        queue: Arc<Queue>,
        config: &SorafsStreamTokenGatewayNativeConfig,
        qualification: Qualification,
    ) -> Result<Self, Error> {
        let operator_public = config
            .operator
            .try_signatory()
            .ok_or(Error::BindingMismatch)?;
        let observer_public = config
            .observer
            .try_signatory()
            .ok_or(Error::BindingMismatch)?;
        let recorder_public = config
            .reputation_recorder
            .try_signatory()
            .ok_or(Error::BindingMismatch)?;
        if recorder_public == operator_public
            || recorder_public == observer_public
            || recorder_public.algorithm() != Algorithm::Ed25519
            || config.reputation_recorder_credential == config.operator_credential
            || config.reputation_recorder_credential == config.observer_credential
            || operator_public == observer_public
            || operator_public.algorithm() != Algorithm::Ed25519
            || observer_public.algorithm() != Algorithm::Ed25519
            || config.operator_credential == config.observer_credential
            || config.fee_payment.validate().is_err()
        {
            return Err(Error::BindingMismatch);
        }
        let operator_key = load_key(&config.operator_credential, operator_public)?;
        let observer_key = load_key(&config.observer_credential, observer_public)?;
        let reputation_recorder_key =
            load_key(&config.reputation_recorder_credential, recorder_public)?;
        Ok(Self {
            state,
            queue,
            qualification,
            operator: config.operator.clone(),
            operator_key,
            observer: config.observer.clone(),
            observer_key,
            reputation_recorder: config.reputation_recorder.clone(),
            reputation_recorder_key,
            fee_payment: config.fee_payment.clone(),
            #[cfg(test)]
            sign_calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    pub(super) fn operator(&self) -> &AccountId {
        &self.operator
    }
    pub(super) fn observer(&self) -> &AccountId {
        &self.observer
    }
    pub(super) fn sign(
        &self,
        instruction: &MutateSorafsStreamTokenGateway,
        observer: bool,
        deadline: Instant,
    ) -> Result<SignedTransaction, Error> {
        remaining(deadline)?;
        #[cfg(test)]
        self.sign_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        instruction.request.validate()?;
        let request = &instruction.request;
        let is_check = matches!(&request.action, Action::Check(_));
        if matches!(&request.action, Action::Configure(_))
            || is_check != observer
            || request.network_id != *self.state.network_id_ref()
            || request.gateway_id != self.qualification.gateway_id
            || request.expected_policy_revision != self.qualification.revision
            || request.expected_policy_digest != self.qualification.policy_digest
        {
            return Err(Error::BindingMismatch);
        }
        if let Action::Check(check) = &request.action {
            if check.expected_operator != self.operator || check.expected_observer != self.observer
            {
                return Err(Error::BindingMismatch);
            }
        }
        let (authority, key) = if observer {
            (&self.observer, &self.observer_key)
        } else {
            (&self.operator, &self.operator_key)
        };
        // A fresh full-width signed submission identity makes first mutation versus exact
        // replay unambiguous even when two identical actions are signed in the same millisecond.
        let mut nonce = [0u8; 32];
        rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut nonce)
            .map_err(|_| Error::Unavailable)?;
        if nonce == [0; 32] {
            return Err(Error::Unavailable);
        }
        let mut metadata = iroha_model_base::metadata::Metadata::default();
        metadata.insert(
            "stream_token_gateway_submission_id"
                .parse()
                .expect("static metadata name"),
            iroha_primitives::json::Json::new(hex::encode(nonce)),
        );
        let mut builder = TransactionBuilder::new(
            *self.state.network_id_ref(),
            authority.clone(),
            self.fee_payment.clone(),
        )
        .with_instructions([instruction.clone()])
        .with_metadata(metadata);
        // The signed TTL is the remaining enclosing budget, never a fresh phase timeout.
        // Millisecond truncation prevents a sub-ms residual budget becoming an unbounded TTL.
        let ttl_ms: u64 = remaining(deadline)?
            .as_millis()
            .try_into()
            .map_err(|_| Error::Unavailable)?;
        if ttl_ms == 0 {
            return Err(Error::Unavailable);
        }
        builder.set_ttl(Duration::from_millis(ttl_ms));
        let signed = builder
            .try_sign(key.private_key())
            .map_err(|_| Error::Unavailable)?;
        remaining(deadline)?;
        Ok(signed)
    }
    /// Sign only the exact current payload exposed by a publication-leased Core capability.
    pub(super) fn sign_reputation_delivery(
        &self,
        delivery: &iroha_core::query::stream_token_gateway::observation::VerifiedStreamTokenReputationDeliveryV1<'_>,
        deadline: Instant,
    ) -> Result<SignedTransaction, Error> {
        remaining(deadline)?;
        let intent = delivery.append_intent().ok_or(Error::StaleOrRevoked)?;
        if intent.network_id != *self.state.network_id_ref()
            || intent.record.admitted_under.gateway_id != self.qualification.gateway_id
            || intent.payload.authority != self.reputation_recorder
        {
            return Err(Error::BindingMismatch);
        }
        // No local creation time, nonce, metadata, fee choice or TTL can alter this recipe.
        let signed = TransactionBuilder::from_payload(intent.payload.clone())
            .map_err(|_| Error::SubstitutedOutcome)?
            .try_sign(self.reputation_recorder_key.private_key())
            .map_err(|_| Error::Unavailable)?;
        if signed.payload() != &intent.payload {
            return Err(Error::SubstitutedOutcome);
        }
        remaining(deadline)?;
        Ok(signed)
    }
    pub(super) fn submit_and_wait(
        &self,
        signed: &SignedTransaction,
        deadline: Instant,
    ) -> Result<[u8; 32], Error> {
        remaining(deadline)?;
        let hash = TransactionEntrypoint::External(signed.clone()).hash();
        let (drift, limits) = self.state.transaction_admission_limits();
        let accepted = AcceptedTransaction::accept(
            signed.clone(),
            self.state.network_id_ref(),
            drift,
            limits,
            self.state.crypto().as_ref(),
        )
        .map_err(|_| Error::Unavailable)?;
        let plan = self
            .queue
            .route_plan_with_state(&accepted, &self.state)
            .map_err(|_| Error::Unavailable)?;
        remaining(deadline)?;
        // Never replace or resubmit this signed envelope after a queue attempt, including errors.
        self.queue
            .push_with_lane_with_state_and_routing_plan(accepted, &self.state, plan)
            .map_err(|_| Error::Ambiguous)?;
        loop {
            remaining(deadline).map_err(|_| Error::Ambiguous)?;
            // Retain any local read refusal until this exact queued envelope is retried.
            let mut deferred_read = None;
            if let Some(height) = self.state.committed_entrypoint_height(&hash) {
                let view = self.state.view();
                let expected_hash = view.block_hashes().get(height.get() - 1).copied();
                let block = match view.kura().get_block(height, &view.execution_budget()) {
                    Ok(block) => block,
                    Err(iroha_core::execution_attempt::ExecutionAttemptError::Deferred(error)) => {
                        deferred_read = Some(error);
                        None
                    }
                    Err(iroha_core::execution_attempt::ExecutionAttemptError::Rejected(_)) => {
                        return Err(Error::Ambiguous);
                    }
                };
                if let Some(expected_hash) = expected_hash
                    && view.kura().get_durable_block_hash(height) == Some(expected_hash)
                    && let Some(block) = block
                    && block.hash() == expected_hash
                    && block.commit_certificate().is_some()
                    && let Some((index, _)) = block.network_entrypoints().enumerate().find(|(_, entry)| {
                        matches!(entry, TransactionEntrypoint::External(actual) if actual == signed)
                    })
                    && let Ok(index) = u32::try_from(index)
                    && block.network_output_at(index).is_some()
                {
                    // Only a readiness hint. A failed native action also appears in this index.
                    // The purpose-specific opaque Check authenticates success and original rows;
                    // neither this presence test nor the certificate's presence grants authority.
                    remaining(deadline).map_err(|_| Error::Ambiguous)?;
                    return Ok(*hash.as_ref());
                }
            }
            std::thread::sleep(
                remaining(deadline)
                    .map_err(|_| Error::Ambiguous)?
                    .min(Duration::from_millis(25)),
            );
            drop(deferred_read);
        }
    }
}
fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(Error::Unavailable)
}
fn load_key(path: &Path, expected: &PublicKey) -> Result<KeyPair, Error> {
    let bytes = load_bounded_runtime_credential_v1(path, 2, 16 * 1024 + 256)
        .map_err(|_| Error::Unavailable)?;
    let text = bytes
        .strip_suffix(b"\n")
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or(Error::Unavailable)?;
    let private: ExposedPrivateKey = text.parse().map_err(|_| Error::Unavailable)?;
    let canonical = Zeroizing::new(
        private
            .try_to_multihash_string()
            .map_err(|_| Error::Unavailable)?,
    );
    if canonical.as_str() != text {
        return Err(Error::Unavailable);
    }
    let key = KeyPair::from_private_key(private.0).map_err(|_| Error::Unavailable)?;
    if key.public_key() != expected {
        return Err(Error::BindingMismatch);
    }
    Ok(key)
}
