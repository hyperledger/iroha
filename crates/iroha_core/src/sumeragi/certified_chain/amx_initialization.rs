//! The real AMX borrower's original constructor acquisition, retained through refusal.
//!
//! Shared native I/O and signed-genesis authentication remain the only kernels. This stage
//! supplies neither result finality nor a lifetime-free recovery job. The same raw frame and
//! prepaid body transfer into CertifiedChain before this empty stage retires.

use super::*;
use iroha_data_model::{
    block::SharedSignedBlock,
    sumeragi_finality::{OriginalGenesisRead, OriginalGenesisReadError},
};

/// Private original-source initialization used by the native AMX reader.
/// An unfinished stage retains its exact pool, slot, raw bytes and prepaid body.
pub(crate) struct AmxChainInitialization<'v, V: StateReadOnly> {
    view: &'v V,
    // Retire completed policy values/charges before the body/raw source and pool.
    authentication: Option<OriginalGenesisRead>,
    body: Option<SharedSignedBlock>,
    acquisition: Option<native_acquisition::NativeCarrierAcquisition<'v>>,
    completed: bool,
}
impl<'v, V: StateReadOnly> AmxChainInitialization<'v, V> {
    /// Select the same State-pinned genesis identity as CertifiedChain::new, without I/O.
    pub(crate) fn new(view: &'v V) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        Ok(Self {
            view,
            authentication: None,
            body: None,
            acquisition: Some(Self::acquisition(view)?),
            completed: false,
        })
    }

    fn acquisition(
        view: &'v V,
    ) -> Result<
        native_acquisition::NativeCarrierAcquisition<'v>,
        ExecutionAttemptError<ChainReadError>,
    > {
        let index = NonZeroUsize::new(1).expect("the fixed signed genesis height is nonzero");
        let expected = view.block_hashes().get(index.get() - 1).copied().ok_or(
            ChainReadError::NotCommitted {
                height: GENESIS_HEIGHT,
            },
        )?;
        Ok(native_acquisition::NativeCarrierAcquisition::new(
            view.kura(),
            index,
            expected,
            view.execution_budget(),
            usize::MAX,
        ))
    }

    #[cfg(test)]
    pub(crate) fn frame_for_test(&self) -> Option<&crate::kura::NativeFrameBytes> {
        self.acquisition
            .as_ref()
            .and_then(|original| original.bytes_for_test())
    }

    /// Observe the original delivered body identity without constructing or cloning it.
    #[cfg(test)]
    pub(crate) fn body_for_test(&self) -> Option<&SharedSignedBlock> {
        self.body.as_ref()
    }

    /// Complete only after the unchanged signed-genesis validator succeeds.
    /// No refusal consumes this original acquisition, and success moves it into the chain.
    pub(crate) fn complete(
        &mut self,
    ) -> Result<CertifiedChain<'v, V>, ExecutionAttemptError<ChainReadError>> {
        if self.completed {
            return Err(ChainReadError::NotInView {
                height: GENESIS_HEIGHT,
            }
            .into());
        }
        #[cfg(all(test, sumeragi_core_mutation = "HC204"))]
        if self.acquisition.is_none() {
            // Only the deliberate HC204 omission recreates a discarded original.
            self.acquisition = Some(Self::acquisition(self.view)?);
        }
        let original = self
            .acquisition
            .as_mut()
            .expect("original constructor stage");
        if self.body.is_none() {
            match original.complete() {
                Ok(body) => self.body = Some(body),
                Err(cause) => {
                    #[cfg(all(test, sumeragi_core_mutation = "HC204"))]
                    {
                        // Restore only the former lost-acquisition bug. The next call still
                        // runs original I/O and all validators, but reads a replacement frame.
                        self.acquisition = None;
                    }
                    return Err(cause);
                }
            }
        } else {
            original.recheck_original_source()?;
        }
        #[cfg(all(test, sumeragi_core_mutation = "HC215"))]
        {
            // Deliberately abandon only the completed original policy stage.
            // Source rechecks, canonical authentication and decoder limits still run.
            self.authentication = None;
        }
        if self.authentication.is_none() {
            self.authentication = Some(
                OriginalGenesisRead::new(
                    self.body.as_ref().expect("original native body").clone(),
                    &self.view.execution_budget(),
                )
                .map_err(original_authentication_error)?,
            );
        }
        let authentication = self
            .authentication
            .as_mut()
            .expect("original genesis policy owner");
        let genesis = self.body.as_ref().expect("original native body").clone();
        let (epoch, instance) = authenticate_genesis_with(
            &genesis,
            self.view.network_id(),
            self.view.chain_id(),
            || {
                authentication
                    .authenticate()
                    .map_err(original_authentication_error)
            },
        )?;
        // TODO(S6): partial first-policy, epoch/result/authority graph retention and
        // exact nested funding remain separate original acquisition boundaries.
        let mut chain = CertifiedChain::from_authenticated_genesis(
            ChainSource::State(self.view),
            genesis,
            epoch,
            instance,
        );
        chain._amx_genesis_authentication = self.authentication.take();
        // Retain the very same bytes/descriptor after body delivery. Prefix retries lend
        // chain.genesis and recheck this source; they never call complete a second time.
        chain.amx_genesis_source = self.acquisition.take();
        self.body = None;
        self.completed = true;
        Ok(chain)
    }
}

// Preserve physical admission identity before a deterministic source projection.
fn original_authentication_error(
    cause: OriginalGenesisReadError,
) -> ExecutionAttemptError<ChainReadError> {
    match cause {
        OriginalGenesisReadError::Validation(cause) => {
            crate::execution_attempt::genesis_read_attempt_error(cause, |_| {
                ChainReadError::ForeignGenesis
            })
        }
        OriginalGenesisReadError::Allocation(iroha_allocation::ChargedBufferError::Admission(
            cause,
        )) => ExecutionAttemptError::Deferred(cause.into()),
        OriginalGenesisReadError::Allocation(iroha_allocation::ChargedBufferError::Allocator {
            ..
        }) => ExecutionAttemptError::Deferred(
            ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
        ),
        OriginalGenesisReadError::ForeignPool => ChainReadError::ForeignGenesis.into(),
    }
}

#[cfg(test)]
mod tests;
