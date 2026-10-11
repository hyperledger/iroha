//! One original terminal AMX carrier, retaining successful target/gap work across refusal.
//!
//! This is a private consumer of the existing native verifier, not another finality algorithm.
//! A gap moves into the original prefix only after every fallible successor check succeeds.
//! The terminal target moves once into the AMX archive reader, without cloning its result into
//! another tip. The borrowed chain retains the actual predecessor/genesis owners until normal
//! scoped retirement. Constructor/genesis-prefix partial work, nested graph funding and durable
//! Worker/restart relay ownership remain separate TODOs; no signing authority is supplied here.

use super::*;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_data_model::block::SharedSignedBlock;

// Field order retires decoded result/body owners before raw source bytes and pool handles.
struct OriginalReceipt<'kura> {
    committed: Option<ChargedBuffer<CommittedBlock>>,
    body: Option<SharedSignedBlock>,
    acquisition: native_acquisition::NativeCarrierAcquisition<'kura>,
}
impl<'kura> OriginalReceipt<'kura> {
    fn new<V: StateReadOnly + ?Sized>(
        view: &'kura V,
        height: u64,
        budget: &AllocationBudget,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        let index = usize::try_from(height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(ChainReadError::NotCommitted { height })?;
        let expected = view
            .block_hashes()
            .get(index.get() - 1)
            .copied()
            .ok_or(ChainReadError::NotCommitted { height })?;
        Ok(Self {
            committed: None,
            body: None,
            acquisition: native_acquisition::NativeCarrierAcquisition::new(
                view.kura(),
                index,
                expected,
                budget.clone(),
                usize::MAX,
            ),
        })
    }

    fn acquire_body(&mut self) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        // A retained body does not waive original slot/journal membership on retry.
        if self.body.is_some() || self.committed.is_some() {
            return self.acquisition.original_source();
        }
        self.body = Some(self.acquisition.complete()?);
        Ok(())
    }

    fn decode(
        &mut self,
        height: u64,
        prefix: &mut VerifiedPrefix,
        budget: &AllocationBudget,
    ) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        self.acquire_body()?;
        if self.committed.is_none() {
            // Clone only the original immutable body handle. A partial result decoder drops;
            // the same actual body/bytes and the caller's cumulative context survive refusal.
            let original = read_frame_admitted(
                self.body
                    .as_ref()
                    .expect("original acquired carrier")
                    .clone(),
                height,
                &mut prefix.validation,
                budget,
            )?;
            self.committed = Some(original);
            self.body = None;
        }
        Ok(())
    }

    fn borrowed(&self) -> &CommittedBlock {
        &self
            .committed
            .as_ref()
            .expect("original decoded receipt")
            .as_slice()[0]
    }

    fn take(&mut self) -> CommittedBlock {
        self.committed
            .as_mut()
            .expect("original decoded receipt")
            .pop()
            .expect("the exact initialized original slot")
    }
}

// Inline state allocates no wrapper or identity graph. Each nonzero physical receipt slot,
// raw frame and shared carrier control is admitted by its actual existing source budget.
pub(super) struct TerminalSelection<'kura> {
    target: OriginalReceipt<'kura>,
    gap: Option<OriginalReceipt<'kura>>,
    height: u64,
    delivered: bool,
    budget: AllocationBudget,
}
impl TerminalSelection<'_> {
    pub(super) const fn delivered(&self) -> bool {
        self.delivered
    }
}

#[cfg(test)]
impl<'v, V: StateReadOnly + ?Sized> CertifiedChain<'v, V> {
    // One actual completed target observation; the test callback can apply real pool pressure
    // but cannot replace a carrier, result, source or verifier outcome.
    pub(crate) fn probe_terminal_target_once(
        &mut self,
        observe: impl FnOnce(&CommittedBlock) + Send + Sync + 'v,
    ) -> Result<(), ChainReadError> {
        if self.terminal.is_some() || self.terminal_probe.get_mut().is_some() {
            return Err(ChainReadError::NotInView { height: 0 });
        }
        *self.terminal_probe.get_mut() = Some(Box::new(observe));
        Ok(())
    }
}

impl<V: StateReadOnly + ?Sized> CertifiedChain<'_, V> {
    #[cfg(test)]
    pub(crate) fn terminal_target_for_test(&self) -> Option<&CommittedBlock> {
        self.terminal
            .as_ref()?
            .target
            .committed
            .as_ref()?
            .as_slice()
            .first()
    }

    #[cfg(test)]
    pub(crate) fn terminal_frame_for_test(&self) -> Option<&crate::kura::NativeFrameBytes> {
        self.terminal.as_ref()?.target.acquisition.bytes_for_test()
    }

    // Only the actual move-only AMX reader uses terminal selection. Refusal keeps the original
    // acquisition in this chain; another height cannot clobber a pending or delivered request.
    pub(crate) fn certified_terminal_amx(
        &mut self,
        height: u64,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<ChainReadError>> {
        let ChainSource::State(view) = &self.source else {
            return Err(ChainReadError::NotInView { height }.into());
        };
        let budget = view.execution_budget();
        budget.with_deferred_refund_notifications(|_| self.select_terminal_amx(height, &budget))
    }

    fn select_terminal_amx(
        &mut self,
        height: u64,
        budget: &AllocationBudget,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<ChainReadError>> {
        let ChainSource::State(view) = &self.source else {
            return Err(ChainReadError::NotInView { height }.into());
        };
        let view = *view;
        if !budget.same_pool(&view.execution_budget()) {
            return Err(ChainReadError::NotInView { height }.into());
        }
        if let Some(pending) = &self.terminal {
            if pending.height != height || pending.delivered || !pending.budget.same_pool(budget) {
                return Err(ChainReadError::NotInView { height }.into());
            }
        } else {
            self.terminal = Some(TerminalSelection {
                target: OriginalReceipt::new(view, height, budget)?,
                gap: None,
                height,
                delivered: false,
                budget: budget.clone(),
            });
        }
        // Preserve the original target-body-before-genesis-prefix order. Once acquired, the
        // same body remains even if genesis initialization or result decoding later refuses.
        self.terminal
            .as_mut()
            .expect("original terminal selection")
            .target
            .acquire_body()?;
        let mut cursor = self.prefix.lock();
        self.prepare_certificate_prefix(&mut cursor, height)?;
        let prefix = cursor.as_mut().expect("authenticated genesis cursor");
        let context = PrefixVerifierContext {
            instance: self.instance,
        };
        let pending = self.terminal.as_mut().expect("original terminal selection");
        pending.target.decode(height, prefix, budget)?;
        #[cfg(test)]
        if let Some(observe) = self.terminal_probe.lock().take() {
            observe(pending.target.borrowed());
        }
        if height == GENESIS_HEIGHT {
            let committed = pending.target.borrowed();
            if committed.core_hash != prefix.tip.core_hash || committed.result != prefix.tip.result
            {
                return Err(ChainReadError::ForeignGenesis.into());
            }
            let certificate =
                context.prepare_certificate(committed, &prefix.authority, None, None)?;
            pending.target.acquisition.original_source()?;
            pending.delivered = true;
            return Ok(certificate.into_certified(pending.target.take()));
        }
        while prefix
            .tip
            .height
            .checked_add(1)
            .is_some_and(|next| next < height)
        {
            let next = prefix.tip.height + 1;
            if pending.gap.is_none() {
                pending.gap = Some(OriginalReceipt::new(view, next, budget)?);
            }
            let gap = pending
                .gap
                .as_mut()
                .expect("same original missing predecessor");
            let prepared = (|| {
                gap.decode(next, prefix, budget)?;
                let prepared = context.prepare_advance(prefix, gap.borrowed(), None)?;
                gap.acquisition.original_source()?;
                pending.target.acquisition.original_source()?;
                Ok::<_, ExecutionAttemptError<ChainReadError>>(prepared)
            })();
            let prepared = match prepared {
                Ok(prepared) => prepared,
                Err(cause) => {
                    #[cfg(all(test, sumeragi_core_mutation = "HC188"))]
                    if matches!(&cause, ExecutionAttemptError::Deferred(_)) {
                        // Deliberately forget only completed target-result work after a later
                        // genuine predecessor refusal. Authentication and source guards stay.
                        pending.target.committed = None;
                    }
                    return Err(cause);
                }
            };
            // The private prepared value proves all fallible checks finished. Move the exact
            // gap graph into its original predecessor cursor; never clone a returned receipt.
            prefix.tip = gap.take();
            prefix.schedule = prepared.schedule;
            prefix.authority = prepared.authority;
            prefix.proof_source = prepared.proof_source;
            drop(prepared.certificate);
            pending.gap = None;
        }
        // Full fallible schedule advancement must finish even though this terminal result
        // intentionally does not become another retained prefix tip.
        let prepared = context.prepare_advance(prefix, pending.target.borrowed(), None)?;
        pending.target.acquisition.original_source()?;
        pending.delivered = true;
        Ok(prepared.certificate.into_certified(pending.target.take()))
    }
}

#[cfg(test)]
mod tests;
