//! The one native wallet implementation (design §3.1, §3.2 and §6, integration decision 8).
//!
//! The Rust SDK and the CLI call it directly; Kotlin and Swift reach it through their native
//! bridges. It never transmits a secret and never proves remotely.
//!
//! - [`CredentialHandleV1`] owns one credential secret (48 bytes, erased on drop) bound to one
//!   binding body. A fresh secret is drawn from the operating system for every body; an
//!   entropy failure produces no credential. The secret can be exported and imported as
//!   erasing bytes for the caller's owner-only storage.
//! - [`prepare_registration_v1`] produces the registration of a seat: a fresh 112-byte tape
//!   per proving invocation, and a retry of the unchanged statement with a fresh tape when
//!   the counter range is exhausted, up to [`MAX_PROVING_ATTEMPTS_V1`] invocations.
//! - [`BallotDisclosureV1`] states what the ballot does not hide; originating a choice needs
//!   a local [`BallotDisclosureAcknowledgementV1`] of exactly its five statements, which is
//!   never transmitted.
//! - The choice lock ([`CredentialHandleV1::lock_choice_v1`]) fixes the complete vote
//!   statement and its authorization digest before any proof exists. The caller persists the
//!   lock record and confirms it ([`CredentialHandleV1::confirm_choice_persisted_v1`]) before
//!   proving; re-proving after a crash can only reproduce the locked statement, so one
//!   credential never authorizes two different statements in its scope.
//! - [`prepare_ballot_v1`] proves the locked statement, mines the stamp at the frozen
//!   difficulty and returns the canonical envelope as an originated
//!   [`BallotSubmissionV1`]; [`BallotSubmissionV1::relay_v1`] wraps an envelope prepared
//!   elsewhere, so relaying is distinguishable from originating a choice.
//! - [`WalletJobV1`] runs either preparation on its own thread with finish-and-discard
//!   cancellation (`specs/parliament_ballot_prover_lifecycle.md`): a cancellation request
//!   suppresses publication and stops the stamp search cooperatively, while completion is
//!   acknowledged only by finishing or dropping the job.
//!
//! Network metadata is not protected by anything here: submission transport is the caller's,
//! and registration and ballot traffic must use separate clients.

mod credential;
mod disclosure;
mod job;
mod prepare;

use iroha_data_model::governance::anonymous_ballot::{
    AnonymousBallotCodecErrorV1, FixedBytesErrorV1,
};
use iroha_parliament_ballot_proof::proving::{ProveError, StatementError};

pub use self::{
    credential::{BallotIntentV1, CREDENTIAL_SECRET_BYTES, CredentialHandleV1},
    disclosure::{BallotDisclosureAcknowledgementV1, BallotDisclosureV1, DisclosureStatementV1},
    job::{
        CancellationV1, JobOutcomeV1, JobStatusV1, WalletCancelHandleV1, WalletJobV1,
        spawn_ballot_preparation_v1, spawn_registration_v1,
    },
    prepare::{
        BallotPreparationOptionsV1, BallotSubmissionV1, MAX_PROVING_ATTEMPTS_V1,
        SubmissionOriginV1, prepare_ballot_v1, prepare_registration_v1,
    },
};
use crate::{
    EntropyUnavailableV1, context::ContextErrorV1, inputs::ProofInputErrorV1, stamp::StampErrorV1,
};

/// Why a wallet operation produced nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletErrorV1 {
    /// The operating system's random source failed: no secret, tape or nonce was drawn and
    /// nothing was proved.
    #[error(transparent)]
    Entropy(#[from] EntropyUnavailableV1),
    /// A typed value could not become a proof input.
    #[error(transparent)]
    Inputs(#[from] ProofInputErrorV1),
    /// A ballot context is invalid.
    #[error(transparent)]
    Context(#[from] ContextErrorV1),
    /// The credential belongs to another body than the ballot context.
    #[error("the credential belongs to another body")]
    ForeignBody,
    /// The credential's commitment is not on the sealed list.
    #[error("the credential's commitment is not on the sealed list")]
    NotOnSealedList,
    /// The acknowledgement covers another network, scope, policy or roster.
    #[error("the disclosure acknowledgement is for another ballot")]
    DisclosureMismatch,
    /// The acknowledgement does not cover exactly the five disclosure statements.
    #[error("the acknowledgement does not cover exactly the five disclosure statements")]
    IncompleteAcknowledgement,
    /// The credential's choice is already locked to another statement.
    #[error("the credential's choice is already locked to another statement")]
    ChoiceLocked,
    /// No choice is locked for this ballot.
    #[error("no choice is locked for this ballot")]
    ChoiceNotLocked,
    /// The choice lock has not been confirmed persisted.
    #[error("the choice lock has not been confirmed persisted")]
    ChoiceNotPersisted,
    /// A choice record does not belong to this credential and ballot, or is not the lock.
    #[error("the choice record does not match this credential and ballot")]
    ChoiceRecordMismatch,
    /// Every proving invocation exhausted its counter range.
    #[error("all {attempts} proving invocations exhausted their counter range")]
    ProvingExhausted {
        /// Invocations made, each with a fresh tape.
        attempts: u8,
    },
    /// The prover refused (for example a secret that is not a witness).
    #[error(transparent)]
    Prove(#[from] ProveError),
    /// A proof statement could not be built.
    #[error(transparent)]
    Statement(#[from] StatementError),
    /// The stamp search failed.
    #[error(transparent)]
    Stamp(StampErrorV1),
    /// An encoding could not be produced or read.
    #[error(transparent)]
    Codec(#[from] AnonymousBallotCodecErrorV1),
    /// The prover returned a proof of another length than the candidate row's.
    #[error(transparent)]
    ProofBytes(#[from] FixedBytesErrorV1),
    /// Cancellation was requested; no result is published.
    #[error("the operation was cancelled and its result discarded")]
    Cancelled,
    /// A worker thread could not be started.
    #[error("a wallet worker thread could not be started")]
    Worker,
}

impl From<StampErrorV1> for WalletErrorV1 {
    fn from(error: StampErrorV1) -> Self {
        match error {
            StampErrorV1::Cancelled => Self::Cancelled,
            StampErrorV1::Entropy(error) => Self::Entropy(error),
            error => Self::Stamp(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_cancellation_and_entropy_failures_keep_their_meaning() {
        assert_eq!(
            WalletErrorV1::from(StampErrorV1::Cancelled),
            WalletErrorV1::Cancelled
        );
        assert_eq!(
            WalletErrorV1::from(StampErrorV1::Entropy(EntropyUnavailableV1)),
            WalletErrorV1::Entropy(EntropyUnavailableV1)
        );
        assert_eq!(
            WalletErrorV1::from(StampErrorV1::Worker),
            WalletErrorV1::Stamp(StampErrorV1::Worker)
        );
        assert!(
            !WalletErrorV1::ProvingExhausted { attempts: 4 }
                .to_string()
                .is_empty()
        );
        let short =
            iroha_data_model::governance::anonymous_ballot::BallotProofBytesV1::new(Vec::new())
                .expect_err("empty proof");
        assert_eq!(WalletErrorV1::from(short), WalletErrorV1::ProofBytes(short));
    }
}
