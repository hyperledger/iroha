//! Compact owner-private root exports from original executed custody and native certificates.
//!
//! These projections never include child transactions, block bodies, writes or contract code.
//! The owner authorizes registration on the parent; a successor certificate authenticates the
//! locally executed genesis result through its parent-result link.

use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    private_dataspace::{
        PrivateDataspaceAnchor, PrivateDataspaceAnchorError, PrivateDataspaceRegistration,
    },
    sumeragi_finality::{authenticated_genesis, signed_genesis_consensus_metadata},
};

use super::{
    certified_chain::{CertifiedChain, ChainReadError},
    lanes::routing::committed_root_scope,
};
use crate::{
    execution_attempt::{ExecutionAttemptError, ExecutionDeferred},
    state::StateReadOnly,
};

/// Why an owner-private root cannot provide an authenticated compact export.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// Original local read refusal; no custody or profile verdict was completed.
    #[error(transparent)]
    Deferred(#[from] ExecutionDeferred),
    /// Original native execution or quorum custody is unavailable or invalid.
    #[error(transparent)]
    Custody(#[from] ChainReadError),
    /// The root is unbound, global or inconsistent with its original signed genesis.
    #[error("private root export refused: {0}")]
    Scope(String),
    /// The bounded public private-root profile is invalid.
    #[error(transparent)]
    Profile(#[from] PrivateDataspaceAnchorError),
}

impl From<ExecutionAttemptError<ChainReadError>> for ExportError {
    fn from(error: ExecutionAttemptError<ChainReadError>) -> Self {
        match error {
            ExecutionAttemptError::Rejected(error) => Self::Custody(error),
            ExecutionAttemptError::Deferred(reason) => Self::Deferred(reason),
        }
    }
}

/// Project the exact signed private root, original executed genesis result and epoch PoPs.
///
/// This local execution claim is submitted only with the parent's owner authorization.
/// No public genesis body or private transaction is required by the parent registration.
///
/// # Errors
/// Refuses missing original execution custody, global or changed scope and invalid profiles.
pub fn registration(
    view: &impl StateReadOnly,
) -> Result<PrivateDataspaceRegistration, ExportError> {
    let chain = CertifiedChain::new(view)?;
    registration_from_chain(view, &chain)
}

fn registration_from_chain<V: StateReadOnly>(
    view: &V,
    chain: &CertifiedChain<'_, V>,
) -> Result<PrivateDataspaceRegistration, ExportError> {
    let scope = committed_root_scope(view.world())
        .ok_or_else(|| ExportError::Scope("immutable root scope is absent or invalid".into()))?;
    if !matches!(scope, SumeragiRootScope::Dataspace { .. }) {
        return Err(ExportError::Scope("root is not owner-private".into()));
    }
    let signed = signed_genesis_consensus_metadata(chain.genesis()).map_err(|error| {
        match crate::execution_attempt::genesis_read_attempt_error(error, |error| {
            ExportError::Scope(error.to_string())
        }) {
            ExecutionAttemptError::Rejected(error) => error,
            ExecutionAttemptError::Deferred(reason) => ExportError::Deferred(reason),
        }
    })?;
    if signed.sumeragi_context.root_scope != scope {
        return Err(ExportError::Scope(
            "committed scope differs from signed genesis".into(),
        ));
    }
    // `committed` reads the original executed receipt, not a replaceable result-only journal.
    let genesis = chain.committed(1)?;
    let epoch = authenticated_genesis(chain.genesis())
        .map(|genesis| genesis.into_parts().0)
        .map_err(|error| {
            match crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                ExportError::Scope(error.to_string())
            }) {
                ExecutionAttemptError::Rejected(error) => error,
                ExecutionAttemptError::Deferred(reason) => ExportError::Deferred(reason),
            }
        })?;
    let registration = PrivateDataspaceRegistration::new(
        scope,
        view.chain_id().clone(),
        *view.network_id(),
        genesis.result().0,
        epoch,
    )?;
    if chain.instance().0 != registration.instance {
        return Err(ExportError::Scope(
            "native instance differs from private root".into(),
        ));
    }
    Ok(registration)
}

/// Project an original executed successor and its fully verified native CommitQC.
///
/// # Errors
/// Refuses genesis, invalid scope, missing original custody, invalid exact quorums or profiles.
pub fn anchor(
    view: &impl StateReadOnly,
    height: u64,
) -> Result<PrivateDataspaceAnchor, ExportError> {
    if height < 2 {
        return Err(ExportError::Scope(
            "anchor requires a non-genesis height".into(),
        ));
    }
    let chain = CertifiedChain::new(view)?;
    let registration = registration_from_chain(view, &chain)?;
    let executed = chain.committed(height)?;
    let certified = chain.certified(height)?;
    if executed.id() != certified.id() || executed.block_hash() != certified.block_hash() {
        return Err(ChainReadError::ExecutionMismatch { height }.into());
    }
    let certificate = certified
        .certificate()
        .ok_or(ChainReadError::MissingCertificate { height })?;
    Ok(PrivateDataspaceAnchor::from_certificate(
        &registration,
        certificate,
    )?)
}

#[cfg(test)]
mod tests;
