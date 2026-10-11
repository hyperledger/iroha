//! Explicit administrative registration of the original private AMX participant on its parent.
//! The SNS attachment loop never calls this action. Native CanSetParameters admission remains
//! mandatory. Completion authenticates successful original transaction inclusion, not current
//! registry freshness or any Prepared/Decision relay.

use super::*;
use crate::{
    managed::{
        ManagedTransactionFinality,
        native_operation::{self, Terms},
    },
    verify::finality::FinalitySource,
};
use iroha::config::Config;
use iroha_wallet::operations::{
    AccountService, AmxDataspaceRegistrationRequest, BoundedTransactionOptions,
    NativePreparationPhase, OperationStatus,
};
use std::time::Instant;

const DIRECTORY: &str = "amx-registration";
const ORIGIN: &str = "original.nrt";

/// Separate wallet observation and independently verified historical AMX registration.
#[derive(Clone, Copy, Debug)]
pub struct AmxRegistrationProgress {
    /// Exact saved-transaction observation; Applied by itself is not parent finality.
    pub transaction_status: Option<OperationStatus>,
    /// Exact successful original transaction in an authenticated Global native carrier.
    pub finalized: Option<AmxRegistrationFinality>,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::attachment::AmxRegistrationOriginV1")]
struct Origin {
    identity: AttachmentIdentity,
    administrator: AccountId,
    torii_root: String,
    chain_discriminant: u16,
    terms: Terms,
    checkpoint: Vec<u8>,
}

/// Authenticated result of the sole original administrative transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmxRegistrationFinality {
    /// Successful native RegisterAmxDataspaceV1 execution under the original signer.
    Registered(ManagedTransactionFinality),
    /// The exact original native transaction failed; a later grant never replaces its bytes.
    Rejected(ManagedTransactionFinality),
}
impl From<native_operation::NativeTransactionExecution> for AmxRegistrationFinality {
    fn from(outcome: native_operation::NativeTransactionExecution) -> Self {
        if outcome.applied {
            Self::Registered(outcome.finality)
        } else {
            Self::Rejected(outcome.finality)
        }
    }
}

impl Origin {
    fn validate(
        &self,
        identity: &AttachmentIdentity,
        config: &Config,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        let original_source = &self.identity == identity && self.administrator == config.account;
        if (!cfg!(all(test, sumeragi_deploy_mutation = "DEP6")) && !original_source)
            || self.torii_root != config.torii_api_url.as_str()
            || self.chain_discriminant != config.account_chain_discriminant
        {
            return Err(AttachmentError::Invalid(
                "original AMX administrative source or signer changed",
            ));
        }
        native(self.terms.validate())?;
        native(self.terms.matches(deadline_unix_ms, options))?;
        self.verifier()?;
        Ok(())
    }
    fn verifier(&self) -> Result<FinalityVerifier> {
        native(native_operation::decode_checkpoint(
            &self.checkpoint,
            self.identity.parent_network_id,
            &self.identity.parent_chain_id,
        ))
    }
    fn request(&self, deadline: Instant) -> AmxDataspaceRegistrationRequest {
        AmxDataspaceRegistrationRequest {
            parent_chain_id: self.identity.parent_chain_id.clone(),
            registration: self.identity.registration.clone(),
            deadline_unix_ms: self.terms.requested_deadline_unix_ms,
            options: self.terms.options(deadline),
        }
    }
}

impl AttachmentStore {
    /// Prepare/submit once or recover explicit registration under a separately selected signer.
    ///
    /// Original child, signer, parent endpoint, UTC/fee ceilings and pre-dispatch checkpoint
    /// publish atomically before any signing. Retry/reopen preserve the same wallet journal and
    /// bounded native replay. A fresh I/O deadline cannot renew the original authorization.
    /// The native handler independently requires CanSetParameters; this action grants nothing.
    ///
    /// # Errors
    /// Rejects changed or incomplete original custody/context/fees/time, stale release, exhausted
    /// deadline, failed fresh quorum, unsafe journal or invalid original successful inclusion.
    pub fn advance_amx_registration<S: FinalitySource + ?Sized>(
        &mut self,
        config: &Config,
        bootstrap: &AuthenticatedBootstrap,
        parent: &mut ParentFinalityStore,
        source: &S,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<AmxRegistrationProgress> {
        self.revalidate()?;
        self.require_active()?;
        operations::require_deadline(options.deadline)?;
        self.validate_amx_parent(config, bootstrap, parent)?;
        let account = AccountService::new(config.clone())
            .and_then(|account| match &self.cancellation {
                Some(signal) => account.with_cancellation(Arc::clone(signal)),
                None => Ok(account),
            })
            .and_then(|account| account.with_deadline(options.deadline))
            .map_err(|_| {
                AttachmentError::Operation("cannot open selected AMX administrator wallet")
            })?;

        let (directory, original) = match self.directory.open_child_optional(DIRECTORY)? {
            Some(directory) => {
                validate_inventory(&directory)?;
                let bytes = directory.read(ORIGIN, MAX_RECORD_BYTES)?;
                let original: Origin = norito::decode_canonical_with_limits(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
                .map_err(|_| {
                    AttachmentError::Invalid("invalid original AMX administrative record")
                })?;
                original.validate(&self.record.identity, config, deadline_unix_ms, options)?;
                (directory, original)
            }
            None => {
                parent.observe(source, &rand::random())?;
                self.require_active()?;
                operations::require_deadline(options.deadline)?;
                self.validate_amx_parent(config, bootstrap, parent)?;
                let original = Origin {
                    identity: self.record.identity.clone(),
                    administrator: config.account.clone(),
                    torii_root: config.torii_api_url.to_string(),
                    chain_discriminant: config.account_chain_discriminant,
                    terms: native(Terms::new(deadline_unix_ms, options))?,
                    checkpoint: native(native_operation::checkpoint_bytes(parent.verifier()))?,
                };
                original.validate(&self.record.identity, config, deadline_unix_ms, options)?;
                let bytes = encode_bounded(&original, MAX_RECORD_BYTES)?;
                self.revalidate()?;
                self.require_active()?;
                operations::require_deadline(options.deadline)?;
                self.validate_amx_parent(config, bootstrap, parent)?;
                let directory = self
                    .directory
                    .publish_private_child(DIRECTORY, &[(ORIGIN, &bytes)])?;
                (directory, original)
            }
        };
        validate_inventory(&directory)?;
        let request = original.request(options.deadline);
        let journal = directory.path().join("transaction");
        let preparation = account
            .inspect_amx_dataspace_registration_preparation(&journal, &request)
            .map_err(|_| AttachmentError::Operation("AMX journal differs from original request"))?;
        let was_signed = preparation.phase() == NativePreparationPhase::Signed;
        if preparation.phase() == NativePreparationPhase::Retired {
            return Err(AttachmentError::Invalid(
                "original AMX registration request was retired",
            ));
        }
        require_signed_replay_source(&directory, &preparation)?;
        if was_signed {
            let transaction = preparation.into_signed_transaction().map_err(|_| {
                AttachmentError::Invalid("signed AMX registration has no original transaction")
            })?;
            if let Some(finalized) = native(native_operation::retained_carrier_execution(
                &directory,
                self.record.identity.parent_network_id,
                &self.record.identity.parent_chain_id,
                &transaction,
            ))? {
                if finalized.finality.height <= original.verifier()?.checkpoint().height() {
                    return Err(AttachmentError::Invalid(
                        "AMX carrier predates its original registration request",
                    ));
                }
                self.revalidate()?;
                original.validate(&self.record.identity, config, deadline_unix_ms, options)?;
                return Ok(AmxRegistrationProgress {
                    transaction_status: None,
                    finalized: Some(finalized.into()),
                });
            }
        }
        // A fresh authenticated parent interval is required before any new payload or dispatch.
        parent.observe(source, &rand::random())?;
        self.revalidate()?;
        self.require_active()?;
        operations::require_deadline(options.deadline)?;
        self.validate_amx_parent(config, bootstrap, parent)?;
        if !was_signed {
            let signing = native(original.terms.signing_deadline(options.deadline))?;
            account
                .prepare_amx_dataspace_registration(&original.request(signing), &journal)
                .map_err(|_| {
                    AttachmentError::Operation("AMX preparation failed; retain original journal")
                })?;
        }
        let report = account
            .submit_amx_dataspace_registration(&journal, &request)
            .map_err(|_| {
                AttachmentError::Operation("AMX transaction needs exact journal recovery")
            })?;
        if !matches!(
            report.status,
            OperationStatus::Applied | OperationStatus::Rejected
        ) {
            return Ok(AmxRegistrationProgress {
                transaction_status: Some(report.status),
                finalized: None,
            });
        }
        let transaction = account
            .verify_amx_dataspace_registration_journal(&journal, &request)
            .map_err(|_| {
                AttachmentError::Invalid("AMX registration wire changed after observation")
            })?;
        let height = if report.status == OperationStatus::Applied {
            operations::carrier_height(&report)?.get()
        } else {
            let Some(height) = account
                .rejected_amx_dataspace_registration_carrier_height(&journal, &request)
                .map_err(|_| {
                    AttachmentError::Operation("cannot read original rejected AMX carrier hint")
                })?
            else {
                return Ok(AmxRegistrationProgress {
                    transaction_status: Some(report.status),
                    finalized: None,
                });
            };
            height.get()
        };
        let observed = parent.verifier().checkpoint().height();
        if height <= original.verifier()?.checkpoint().height() {
            return Err(AttachmentError::Invalid(
                "AMX carrier predates its original registration request",
            ));
        }
        let finalized = if height > observed {
            None
        } else {
            let progress = native(native_operation::read_optional(
                &directory,
                "replay.nrt",
                native_operation::MAX_CHECKPOINT_BYTES,
            ))?;
            let progress = progress
                .map(|bytes| {
                    native_operation::decode_checkpoint(
                        &bytes,
                        self.record.identity.parent_network_id,
                        &self.record.identity.parent_chain_id,
                    )
                })
                .transpose();
            let mut verifier = native(native_operation::replay_start(
                original.verifier()?,
                native(progress)?,
                height,
            ))?;
            operations::require_deadline(options.deadline)?;
            native(native_operation::retain_carrier_execution_progress(
                &directory,
                &transaction,
                &mut verifier,
                height,
                source,
                false,
            ))?
            .map(Into::into)
        };
        self.revalidate()?;
        directory.revalidate()?;
        operations::require_deadline(options.deadline)?;
        self.validate_amx_parent(config, bootstrap, parent)?;
        original.validate(&self.record.identity, config, deadline_unix_ms, options)?;
        Ok(AmxRegistrationProgress {
            transaction_status: Some(report.status),
            finalized,
        })
    }

    fn validate_amx_parent(
        &self,
        config: &Config,
        bootstrap: &AuthenticatedBootstrap,
        parent: &ParentFinalityStore,
    ) -> Result<()> {
        let identity = &self.record.identity;
        let release = bootstrap.release();
        let now = native(native_operation::now_ms())?;
        if config.network_id != identity.parent_network_id
            || config.chain.as_str() != identity.parent_chain_id
            || config.account_chain_discriminant != release.account_chain_discriminant
            || config.api_token.is_some()
            || config.basic_auth.is_some()
            || parent.network_name() != identity.parent_name
            || parent.generation() != identity.parent_generation
            || parent.verifier().checkpoint().network_id() != identity.parent_network_id
            || parent.verifier().checkpoint().chain_id() != identity.parent_chain_id
            || release.network_name != identity.parent_name
            || release.generation != identity.parent_generation
            || release.network_id != identity.parent_network_id
            || release.chain_id != identity.parent_chain_id
            || now < release.issued_at_ms
            || now >= release.expires_at_ms
            || !release
                .torii_roots
                .iter()
                .any(|root| root == config.torii_api_url.as_str())
        {
            return Err(AttachmentError::Invalid(
                "AMX administrator selected another or expired authenticated parent",
            ));
        }
        Ok(())
    }
}

// Replay/carrier publication is reachable only after the wallet retained its signed original.
// An absent or rolled-back unsigned prefix cannot authorize replacement signing or dispatch.
fn require_signed_replay_source(
    directory: &PrivateDirectory,
    preparation: &iroha_wallet::operations::VerifiedNativePreparation,
) -> Result<()> {
    if preparation.phase() != NativePreparationPhase::Signed
        && directory.entries(4)?.iter().any(|name| {
            ["replay.nrt", "carrier.nrt"]
                .iter()
                .any(|record| name.as_os_str() == std::ffi::OsStr::new(record))
        })
    {
        return Err(AttachmentError::Invalid(
            "AMX replay evidence has no original signed transaction",
        ));
    }
    Ok(())
}

// This bounded inventory belongs to the sole administrative action, never the SNS journal.
fn validate_inventory(directory: &PrivateDirectory) -> Result<()> {
    let entries = directory.entries(4)?;
    if !entries
        .iter()
        .any(|name| name.as_os_str() == std::ffi::OsStr::new(ORIGIN))
        || entries.iter().any(|name| {
            ![ORIGIN, "transaction", "replay.nrt", "carrier.nrt"]
                .iter()
                .any(|allowed| name.as_os_str() == std::ffi::OsStr::new(*allowed))
        })
    {
        return Err(AttachmentError::Invalid(
            "incomplete or foreign AMX administrative inventory",
        ));
    }
    directory.revalidate()?;
    Ok(())
}

fn native<T>(result: crate::managed::Result<T>) -> Result<T> {
    result.map_err(AttachmentError::NativeOperation)
}

#[cfg(test)]
mod tests;
