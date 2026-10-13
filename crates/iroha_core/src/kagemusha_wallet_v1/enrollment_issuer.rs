//! Closed enrollment orchestration over current provider selection and exclusive native custody.
//!
//! The mandatory deployment runtime authenticates real Torii calls, current provider eligibility
//! observations, private worker channels and rooted signer custody. Public request DATA cannot select
//! any of these owners. Every monetary-authority boundary consumes a fresh signed provider
//! observation retained in the attempt journal before performing its one bound operation.
//! The Torii adapter installs concrete authenticated runtimes and a supervised service thread.
//! TODO: qualify the complete Linux deployment with real platform evidence; component tests
//! do not establish device or deployed-service attestation.

use super::enrollment_journal::{
    EnrollmentAttemptV1, EnrollmentJournalErrorV1, EnrollmentJournalPhaseV1 as Phase,
    EnrollmentJournalV1, EnrollmentSelectionV1,
};
use crate::state::State;
use iroha_config::parameters::actual::{KagemushaEnrollmentIssuer, KagemushaEnrollmentProvider};
use iroha_core_zk::kagemusha_wallet_enrollment_v1::{
    PreKeyDispatchV1, RequestV1, ResultV1,
    issuer_worker::{ActionV1, OutcomeV1, VerifierConfigurationV1, VerifierExchangeV1},
};
use iroha_data_model::{account::AccountId, kagemusha::*};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

mod operations;
mod runtime;
mod selection;
pub use runtime::EnrollmentIssuerRuntimeV1;

/// Closed failure classes. Unavailability never becomes a provider denial or platform verdict.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum EnrollmentIssuerErrorV1 {
    /// A required authenticated runtime, current read, trusted clock or entropy is unavailable.
    #[error("enrollment issuer unavailable")]
    Unavailable,
    /// Request, signature, canonical original or native runtime framing was invalid.
    #[error("enrollment issuer original rejected")]
    Invalid,
    /// Current authenticated selection differs, including account routing or revocation.
    #[error("enrollment issuer current selection differs")]
    Selection,
    /// The private verifier retained a terminal refusal for this consumed attempt, with exactly
    /// one closed reason (design §2.4) that every retry returns unchanged.
    #[error("enrollment evidence refused: code {}", .0.code())]
    Refused(KagemushaWalletEnrollmentRefusalV1),
    /// An authenticated eligibility observation withholds delivery of an Issued outcome with
    /// code 11 (`AccountNotApproved`) or 12 (`AccountFrozen`). The Issued outcome, its exact E6
    /// and its quota share stay retained; a later approving observation returns the same E6.
    #[error("enrollment credential delivery withheld: code {}", .0.code())]
    DeliveryWithheld(KagemushaWalletEnrollmentRefusalV1),
    /// The worker could not decide before any effect; a retry resumes the same claim.
    #[error("enrollment verification outcome pending")]
    Pending,
    /// An effect may have taken place without a retained terminal outcome. Recovery never
    /// repeats the effect: it never verifies again as a first attempt or signs again.
    #[error("enrollment outcome unknown")]
    OutcomeUnknown,
    /// Preserve native custody, uncertainty, conflict and definitive provider denial separately.
    #[error(transparent)]
    Journal(#[from] EnrollmentJournalErrorV1),
}
type Result<T> = std::result::Result<T, EnrollmentIssuerErrorV1>;
use EnrollmentIssuerErrorV1::{
    DeliveryWithheld, Invalid, OutcomeUnknown, Pending, Refused, Selection, Unavailable,
};

/// An in-process authenticated session. It cannot be decoded or constructed from a verdict.
/// Its private cursor and issuer incarnation prevent foreign-owner or stale-attempt use.
pub struct EnrollmentIssuerSessionV1 {
    issuer: [u8; 32],
    dispatch: PreKeyDispatchV1,
    attempt: EnrollmentAttemptV1,
}

/// Exclusive service owner; no worker, signer, provider observation, current selection or clock is optional.
pub struct EnrollmentIssuerV1<R> {
    runtime: R,
    state: Arc<State>,
    journal: EnrollmentJournalV1,
    scope: [u8; 32],
    journal_path: std::path::PathBuf,
    incarnation: [u8; 32],
    last_time_ms: u64,
}

/// Exact journal initialization scope for the explicit provisioning owner.
/// Ordinary service startup opens an existing scope and never calls journal initialization.
///
/// # Errors
/// Returns `Invalid` when `scope` is the all-zero identifier.
pub fn enrollment_issuer_journal_scope_v1(scope: [u8; 32]) -> Result<Vec<u8>> {
    if scope == [0; 32] {
        return Err(Invalid);
    }
    let mut original = b"iroha:kagemusha:enrollment-issuer:v1\0".to_vec();
    original.extend_from_slice(&scope);
    Ok(original)
}

fn random_nonce() -> Result<[u8; 32]> {
    let mut value = [0; 32];
    rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut value)
        .map_err(|_| Unavailable)?;
    if value == [0; 32] {
        return Err(Unavailable);
    }
    Ok(value)
}

fn operation_digest(label: &[u8], original: &[u8]) -> Result<[u8; 32]> {
    if original.is_empty() || original.len() > 768 * 1024 {
        return Err(Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(b"iroha:kagemusha:issuer-eligibility-operation:v1\0");
    hash.update((label.len() as u64).to_le_bytes());
    hash.update(label);
    hash.update((original.len() as u64).to_le_bytes());
    hash.update(original);
    Ok(hash.finalize().into())
}

impl<R: EnrollmentIssuerRuntimeV1> EnrollmentIssuerV1<R> {
    /// Open existing journal custody and bind all mandatory trusted deployment runtimes.
    ///
    /// # Errors
    /// Missing stores, unsafe custody, incomplete configured runtimes or clock/entropy failure
    /// refuse startup. Configuration DATA never supplies an eligibility or signing capability.
    pub fn open(state: Arc<State>, mut runtime: R) -> Result<Self> {
        let config = runtime.current_configuration()?;
        if config.revision == 0 || config.providers.is_empty() {
            return Err(Selection);
        }
        runtime.require_dependencies(&config)?;
        let journal = EnrollmentJournalV1::open(
            &config.journal_dir,
            &enrollment_issuer_journal_scope_v1(config.scope)?,
        )?;
        let mut owner = Self {
            runtime,
            state,
            journal,
            scope: config.scope,
            journal_path: config.journal_dir.clone(),
            incarnation: random_nonce()?,
            last_time_ms: 0,
        };
        owner.now()?;
        Ok(owner)
    }

    fn now(&mut self) -> Result<u64> {
        let value = self.runtime.now_ms()?;
        if value == 0 || value < self.last_time_ms {
            return Err(Unavailable);
        }
        self.last_time_ms = value;
        Ok(value)
    }

    fn require_session(&self, session: &EnrollmentIssuerSessionV1) -> Result<()> {
        if session.issuer != self.incarnation {
            return Err(Selection);
        }
        // The authoritative current attempt decides, before any new observation, worker
        // exchange or signer call: a retained terminal eligibility refusal answers every later
        // operation of every session unchanged, and any other stale cursor is rejected.
        if let Some(reason) = session.attempt.refusal() {
            return Err(Refused(reason));
        }
        if let Some(reason) = self.journal.current_refusal(&session.attempt)? {
            return Err(Refused(reason));
        }
        Ok(())
    }

    /// Authenticate an actual signed Torii envelope and bind the unchanged native dispatch.
    ///
    /// `call` is transport-original authentication material consumed by the mandatory trusted
    /// runtime. It is never an account/actor verdict. The runtime must authenticate exactly
    /// the entire action envelope containing exact `dispatch_original`, including network, freshness
    /// and replay. The associated call type cannot supply a decoded authority verdict.
    /// # Errors
    /// Rejects unsigned/foreign calls, unregistered accounts/assets, current routing changes,
    /// invalid originals, missing Resume attempts or journal uncertainty.
    pub fn authenticate(
        &mut self,
        call: &R::Call,
        dispatch_original: &[u8],
    ) -> Result<EnrollmentIssuerSessionV1> {
        let dispatch = PreKeyDispatchV1::decode(dispatch_original).map_err(|_| Invalid)?;
        // A policy naming an unknown or unqualified vendor adapter is a configuration failure
        // before any E1 is selected, never an E1 outcome.
        iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::require_qualified_android_adapters_v1(
            &dispatch.policy.platform,
        )
        .map_err(|_| Selection)?;
        let account = self.runtime.authenticate_call(call, dispatch_original)?;
        if account != dispatch.account {
            return Err(Selection);
        }
        let account_digest = kagemusha_wallet_account_digest_v1(&account).map_err(|_| Invalid)?;
        let key = self
            .journal
            .request_key(&account_digest, &dispatch.request_id)?;
        let stable = dispatch.stable_selection().map_err(|_| Invalid)?;
        let prior = self.journal.read(&key)?;
        if let Some(prior) = &prior {
            if prior.selection().stable_selection != stable {
                return Err(Selection);
            }
        }
        // A durably retained terminal refusal is recovered from the journal alone: answering
        // it unchanged needs no live provider, worker or signer dependency.
        let terminal = prior
            .as_ref()
            .is_some_and(|prior| prior.refusal().or(prior.worker_refusal()).is_some());
        if !terminal {
            self.current(&dispatch)?;
        }
        let attempt = if let Some(prior) = prior {
            prior
        } else {
            if dispatch.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh {
                return Err(Selection);
            }
            let created_at_ms = self.now()?;
            let selection = EnrollmentSelectionV1 {
                key,
                attempt_id: random_nonce()?,
                created_at_ms,
                expires_at_ms: created_at_ms
                    .checked_add(dispatch.policy.challenge_lifetime_ms)
                    .ok_or(Invalid)?,
                stable_selection: stable,
                challenge: KagemushaWalletEnrollmentChallengeV1 {
                    version: 1,
                    scheme_id: dispatch.scheme.scheme_id(),
                    asset_digest: dispatch.asset.asset_digest(),
                    account_digest,
                    app_policy: dispatch.app.policy_digest().map_err(|_| Invalid)?,
                    enrollment_policy: dispatch.policy.policy_digest().map_err(|_| Invalid)?,
                    issuer_nonce: random_nonce()?,
                },
            };
            self.journal.select(selection)?
        };
        Ok(EnrollmentIssuerSessionV1 {
            issuer: self.incarnation,
            dispatch,
            attempt,
        })
    }
}

#[cfg(test)]
mod tests;
