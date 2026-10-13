//! Standalone finish-and-discard ownership adapter for the synchronous prover.
//!
//! Cancellation controls publication, not execution: one call runs to its
//! ordinary return. `wait`, `finish`, and dropping the job join that call. Only
//! `finish` can release a proof, after input owners have dropped, and its mutex
//! decision is the publication boundary. A cancelled job cannot release bytes.
//! This is an example, not a wallet API or a process-abort cleanup guarantee.
//! TODO: Independent constant-time and comprehensive erasure review remains open.

use std::{
    io,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use iroha_parliament_ballot_proof::{
    credential::CredentialSecret,
    profile::Row,
    proving::{ProveError, ProvingTape},
    registration::{self, RegistrationStatement},
    vote::{self, VoteStatement},
};
use zeroize::Zeroizing;

/// An owned public statement and, for a vote, the secret list position.
pub enum Statement {
    /// Registration statement.
    Registration(RegistrationStatement),
    /// Vote statement and secret list position.
    Vote(VoteStatement, u16),
}

/// Inputs transferred into exactly one synchronous proving invocation.
pub struct Input {
    /// Explicit parameter row.
    pub row: Row,
    /// Statement and optional position.
    pub statement: Statement,
    /// The job owns this secret; no borrowed wallet secret outlives cleanup.
    pub secret: CredentialSecret,
    /// A fresh caller-supplied tape, consumed even on ordinary failure.
    pub tape: ProvingTape,
}

impl Input {
    fn compute(self) -> Result<Zeroizing<Vec<u8>>, ProveError> {
        let Self {
            row,
            statement,
            secret,
            tape,
        } = self;
        let result = match statement {
            Statement::Registration(statement) => {
                registration::prove(row, &statement, &secret, tape)
            }
            Statement::Vote(statement, index) => vote::prove(row, &statement, &secret, index, tape),
        }
        .map(Zeroizing::new);
        // The library borrows the secret. Its owner must drop before any result
        // can be observed, including a successful unpublished completion.
        drop(secret);
        result
    }
}

#[derive(Clone, Copy)]
enum Gate {
    Open,
    Cancelled,
    Closed,
}

/// Result of a cancellation request; only joining acknowledges cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancellation {
    /// This request suppresses any future publication.
    Accepted,
    /// An earlier request already suppressed publication.
    AlreadyRequested,
    /// `finish` has crossed the publication decision boundary.
    TooLate,
}

/// Cloneable control handle; contains no input or proof bytes.
#[derive(Clone)]
pub struct CancelHandle(Arc<Mutex<Gate>>);

impl CancelHandle {
    /// Observe a destructor's cancellation request in allocation-barrier tests.
    #[cfg(test)]
    pub(crate) fn cancellation_requested(&self) -> bool {
        matches!(
            *self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Gate::Cancelled
        )
    }

    /// Suppress publication if the job has not already crossed that boundary.
    /// Does not interrupt the call or acknowledge cleanup.
    pub fn cancel(&self) -> Cancellation {
        let mut gate = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *gate {
            Gate::Open => {
                *gate = Gate::Cancelled;
                Cancellation::Accepted
            }
            Gate::Cancelled => Cancellation::AlreadyRequested,
            Gate::Closed => Cancellation::TooLate,
        }
    }
}

/// Public computation status, with no proof bytes, digest, or secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Computation {
    /// The real synchronous call returned a proof internally.
    Proved,
    /// Ordinary typed proving error.
    Failed(ProveError),
    /// The thread could not join normally. No cleanup claim is made here;
    /// abort profiles terminate the process instead of yielding this value.
    WorkerPanicked,
}

type Completion = Result<Result<Zeroizing<Vec<u8>>, ProveError>, ()>;

/// The sole way a job releases proof bytes.
pub enum Outcome {
    /// Uncancelled completion, after joining and dropping input owners.
    Published(Zeroizing<Vec<u8>>),
    /// Cancelled completion; any computed proof was zeroized and discarded.
    Discarded(Computation),
    /// Ordinary error from an uncancelled completion.
    Failed(ProveError),
    /// Abnormal thread completion; not an erasure attestation.
    WorkerPanicked,
}

/// Non-cloneable job. Dropping it requests cancellation and joins; it does not
/// detach a worker. `mem::forget`, process termination, and abort are excluded.
pub struct Job {
    control: CancelHandle,
    worker: Option<JoinHandle<Result<Zeroizing<Vec<u8>>, ProveError>>>,
    completion: Option<Completion>,
}

impl Job {
    /// Transfer inputs into one worker with an 8 MiB requested stack.
    ///
    /// # Errors
    /// Thread creation failure. The transferred input closure is dropped.
    pub fn spawn(input: Input) -> io::Result<Self> {
        Self::spawn_inner(input, || {}, |_| {})
    }

    fn spawn_inner(
        input: Input,
        before: impl FnOnce() + Send + 'static,
        after: impl FnOnce(Option<&[u8]>) + Send + 'static,
    ) -> io::Result<Self> {
        let worker = thread::Builder::new()
            .name("parliament-prover-lifecycle".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                before();
                let result = input.compute();
                after(result.as_ref().ok().map(|proof| proof.as_slice()));
                result
            })?;
        Ok(Self {
            control: CancelHandle(Arc::new(Mutex::new(Gate::Open))),
            worker: Some(worker),
            completion: None,
        })
    }

    /// Observer injection for allocation tests only, not an example API.
    #[cfg(test)]
    pub(crate) fn spawn_observed(
        input: Input,
        before: impl FnOnce() + Send + 'static,
        after: impl FnOnce(Option<&[u8]>) + Send + 'static,
    ) -> io::Result<Self> {
        Self::spawn_inner(input, before, after)
    }

    /// A handle that can request cancellation from another thread.
    pub fn cancellation(&self) -> CancelHandle {
        self.control.clone()
    }

    /// Join computation and acknowledge ordinary input-owner cleanup, without
    /// releasing a proof. Repeated calls return the same status. Cancellation
    /// remains possible after this method and before `finish`.
    pub fn wait(&mut self) -> Computation {
        if let Some(worker) = self.worker.take() {
            self.completion = Some(worker.join().map_err(|_| ()));
        }
        match self.completion.as_ref() {
            Some(Ok(Ok(_))) => Computation::Proved,
            Some(Ok(Err(error))) => Computation::Failed(*error),
            Some(Err(())) | None => Computation::WorkerPanicked,
        }
    }

    /// Join, then atomically decide whether publication is allowed. A
    /// cancellation accepted before this decision always discards the result.
    pub fn finish(mut self) -> Outcome {
        let status = self.wait();
        let cancelled = {
            let mut gate = self
                .control
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let cancelled = matches!(*gate, Gate::Cancelled);
            *gate = Gate::Closed;
            cancelled
        };
        let completion = self.completion.take();
        if cancelled {
            drop(completion); // Zeroizing proof storage is erased before return.
            Outcome::Discarded(status)
        } else {
            match completion {
                Some(Ok(Ok(proof))) => Outcome::Published(proof),
                Some(Ok(Err(error))) => Outcome::Failed(error),
                Some(Err(())) | None => Outcome::WorkerPanicked,
            }
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if self.worker.is_some() || self.completion.is_some() {
            self.control.cancel();
            self.wait();
            self.completion.take(); // Erase any unpublished proof.
            *self
                .control
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Gate::Closed;
        }
    }
}
