//! Explicit administrative AMX registration through the existing bounded native journal.
//! Structural selection grants no permission; Global native execution still requires
//! CanSetParameters. No SNS-owner authority is inferred and no principal is moved.

use super::bounded::{encode_bounded, validate_options};
use super::*;
use iroha_data_model::{
    block::consensus::SumeragiRootScope, isi::sumeragi_amx::RegisterAmxDataspaceV1,
    private_dataspace::MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES,
    sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES,
};

/// Exact retained child context and explicit original administrative spending authorization.
#[derive(Clone, Debug)]
pub struct AmxDataspaceRegistrationRequest {
    /// Independently selected parent chain label, separate from the child's chain label.
    pub parent_chain_id: String,
    /// Original signed child registration supplied by its retained source owner.
    pub registration: PrivateDataspaceRegistration,
    /// Original finite exclusive Unix-millisecond authorization; recovery never renews it.
    pub deadline_unix_ms: u64,
    /// Explicit fee ceilings and this call's monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

pub(super) fn instruction(
    config: &Config,
    parent_chain_id: &str,
    registration: &PrivateDataspaceRegistration,
    deadline_unix_ms: u64,
) -> Result<InstructionBox> {
    eyre::ensure!(
        !parent_chain_id.is_empty()
            && parent_chain_id.len() <= 4096
            && parent_chain_id == config.chain.as_str()
            && deadline_unix_ms > 0
            && deadline_unix_ms != u64::MAX,
        "AMX registration differs from the selected parent chain or original finite authorization"
    );
    encode_bounded(registration, MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES)?;
    registration.validate()?;
    let SumeragiRootScope::Dataspace {
        parent_network_id,
        dataspace_id,
    } = registration.scope
    else {
        eyre::bail!("AMX registration requires the original private child scope");
    };
    eyre::ensure!(
        parent_network_id == config.network_id,
        "AMX registration selects another parent network"
    );
    let anchor = encode_bounded(&registration.initial_epoch, MAX_RESULT_PREIMAGE_BYTES)?;
    Ok(RegisterAmxDataspaceV1 {
        dataspace: dataspace_id,
        instance: registration.instance,
        anchor,
    }
    .into())
}

pub(super) struct AmxRegistrationExpectation<'a>(pub(super) &'a AmxDataspaceRegistrationRequest);
impl AmxRegistrationExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::AmxDataspaceRegistration {
            parent_chain_id,
            registration,
            deadline_unix_ms,
            terms,
        } = record.operation
        else {
            eyre::bail!("journal differs from the exact administrative AMX purpose");
        };
        validate_options(&self.0.options)?;
        eyre::ensure!(
            parent_chain_id == &self.0.parent_chain_id
                && registration.as_ref() == &self.0.registration
                && *deadline_unix_ms == self.0.deadline_unix_ms
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?
                && terms.deadline_ms <= *deadline_unix_ms
                && record.deadline_ms <= terms.deadline_ms,
            "AMX journal differs from original child, parent, fees or UTC authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect this exact administrative request without HTTP, signing or permission inference.
    /// # Errors
    /// Rejects substituted signer/source/fees/time or unsafe and malformed journal custody.
    pub fn inspect_amx_dataspace_registration_preparation(
        &self,
        journal: &Path,
        expected: &AmxDataspaceRegistrationRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::AmxDataspaceRegistration,
            Some(OperationExpectation::AmxRegistration(
                AmxRegistrationExpectation(expected),
            )),
        )
    }

    /// Retain and sign the sole original registration; submission is separate.
    /// Native permission and accepted execution are not established by this local plan.
    /// # Errors
    /// Rejects changed child/context, malformed or expired original authorization and custody.
    pub fn prepare_amx_dataspace_registration(
        &self,
        request: &AmxDataspaceRegistrationRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        let account = self.with_deadline(request.options.deadline)?;
        if let Some(report) = account.finish_existing_preparation(
            journal,
            NativeOperationKind::AmxDataspaceRegistration,
            Some(OperationExpectation::AmxRegistration(
                AmxRegistrationExpectation(request),
            )),
        )? {
            return Ok(report);
        }
        validate_options(&request.options)?;
        eyre::ensure!(
            request.deadline_unix_ms > current_unix_ms()? && request.deadline_unix_ms != u64::MAX,
            "original administrative AMX authorization expired or is unbounded"
        );
        instruction(
            &self.config,
            &request.parent_chain_id,
            &request.registration,
            request.deadline_unix_ms,
        )?;
        let mut terms = BoundedTerms::new(&request.options)?;
        terms.deadline_ms = terms.deadline_ms.min(request.deadline_unix_ms);
        account.prepare_native(
            NativeOperation::AmxDataspaceRegistration {
                parent_chain_id: request.parent_chain_id.clone(),
                registration: Box::new(request.registration.clone()),
                deadline_unix_ms: request.deadline_unix_ms,
                terms,
            },
            request.options.fee_payment.clone(),
            journal,
        )
    }

    /// Borrow the original signed operation for independent certified-carrier verification.
    /// # Errors
    /// Refuses partial/retired custody or changes to the original request and signing identity.
    pub fn verify_amx_dataspace_registration_journal(
        &self,
        journal: &Path,
        expected: &AmxDataspaceRegistrationRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_amx_dataspace_registration_preparation(journal, expected)?
            .into_signed_transaction()
    }

    /// Read an exact failed transaction's carrier hint; this does not authenticate finality.
    /// # Errors
    /// Rejects altered signed wire, hash/scope, successful details or invalid transport evidence.
    pub fn rejected_amx_dataspace_registration_carrier_height(
        &self,
        journal: &Path,
        expected: &AmxDataspaceRegistrationRequest,
    ) -> Result<Option<std::num::NonZeroU64>> {
        let account = self.with_deadline(expected.options.deadline)?;
        let transaction = account.verify_amx_dataspace_registration_journal(journal, expected)?;
        let client = account.client.client();
        let Some(status) = client.get_transaction_status_response_global(transaction.hash())?
        else {
            return Ok(None);
        };
        eyre::ensure!(
            status.hash == hex::encode(transaction.hash().as_ref()) && status.scope == "global",
            "AMX rejected observation differs from original transaction"
        );
        if status.status.kind != "Rejected" || status.resolved_from != "state" {
            return Ok(None);
        }
        let Some(height) = status
            .status
            .block_height
            .and_then(std::num::NonZeroU64::new)
        else {
            return Ok(None);
        };
        let details = match client
            .get_transaction_details(transaction.hash_as_entrypoint())
            .wrap_err("read exact rejected AMX transaction evidence")
        {
            Ok(details) => details,
            Err(error) if typed_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let TransactionEntrypoint::External(original) = details.transaction.entrypoint() else {
            eyre::bail!("AMX rejected observation has another entrypoint");
        };
        eyre::ensure!(
            details.transaction.result().is_err()
                && original.hash() == transaction.hash()
                && original.encode_wire_v1()? == transaction.encode_wire_v1()?,
            "AMX rejected observation differs from exact failed original execution"
        );
        Ok(Some(height))
    }

    /// Dispatch the exact retained operation at most once, retaining its original marker.
    /// An Applied observation is not independent parent finality.
    /// # Errors
    /// Refuses altered identity/authorization, unsafe custody or invalid transport observations.
    pub fn submit_amx_dataspace_registration(
        &self,
        journal: &Path,
        expected: &AmxDataspaceRegistrationRequest,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::AmxDataspaceRegistration,
                true,
                Some(OperationExpectation::AmxRegistration(
                    AmxRegistrationExpectation(expected),
                )),
            )
    }

    /// Reconcile original signed bytes without submitting, quoting or signing again.
    /// # Errors
    /// Refuses changed source/fees/identity or unsafe custody and invalid observations.
    pub fn resume_amx_dataspace_registration(
        &self,
        journal: &Path,
        expected: &AmxDataspaceRegistrationRequest,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::AmxDataspaceRegistration,
                false,
                Some(OperationExpectation::AmxRegistration(
                    AmxRegistrationExpectation(expected),
                )),
            )
    }
}

#[cfg(test)]
#[path = "operations_amx_registration_tests.rs"]
mod tests;
