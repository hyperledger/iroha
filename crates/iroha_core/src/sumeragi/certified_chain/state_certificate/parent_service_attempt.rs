//! Original parent-service source and authority backing retained by the real worker attempt.
//!
//! Preparation precedes transient overlay/queue-lease allocation. Final authentication still
//! consumes the same native verifier and rechecks the exact captured source and proposal.
//! TODO: nested native body/result decoding and returned signer/output graphs retain their
//! existing incomplete funding contract; this owner does not enable request-funded HTTP reads.

use super::super::{AdmittedFrameRead, funded_authority::FundedAuthorityGraph};
use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::block::SharedSignedBlock;
use iroha_sumeragi::types::HeightConfig;

/// Private attempt custody, not an imported certificate or a reusable State authority.
#[derive(Default)]
pub(crate) struct ParentServicePreparation {
    assembly_parent: Option<SharedSignedBlock>,
    authority: Option<FundedAuthorityGraph>,
    predecessor: Option<ReceiptRead>,
    parent: Option<ReceiptRead>,
    genesis: Option<Carrier>,
    authenticated: Option<(
        Hash32,
        iroha_data_model::block::consensus::SumeragiRootScope,
    )>,
    original: Option<Original>,
}
struct Original {
    kura: Arc<crate::kura::Kura>,
    budget: AllocationBudget,
    tip: crate::state::NativeExecutionTip,
    network: NetworkId,
    chain: [u8; iroha_model_base::chain::MAX_CHAIN_ID_BYTES],
    chain_len: usize,
    genesis: HashOf<IrohaHeader>,
}
struct Carrier {
    body: Option<SharedSignedBlock>,
    acquisition: NativeCarrierAcquisition<'static>,
    height: u64,
    hash: HashOf<IrohaHeader>,
}
struct ReceiptRead {
    frame: AdmittedFrameRead,
    complete: bool,
    carrier: Carrier,
}

fn source(error: ExecutionAttemptError<ChainReadError>) -> ParentServiceError {
    match error {
        ExecutionAttemptError::Rejected(original) => ParentServiceError::NativeSource(original),
        ExecutionAttemptError::Deferred(original) => ParentServiceError::Deferred(original),
    }
}
fn index(height: u64) -> Result<NonZeroUsize, ParentServiceError> {
    usize::try_from(height)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| parent_source_failure("parent-service source height is not addressable"))
}
impl Carrier {
    fn new(
        view: &(impl StateReadOnly + ?Sized),
        height: u64,
        budget: &AllocationBudget,
    ) -> Result<Self, ParentServiceError> {
        let index = index(height)?;
        let hash = *view.block_hashes().get(index.get() - 1).ok_or_else(|| {
            parent_source_failure("parent-service source is outside the original cut")
        })?;
        // The existing native source loader has no independent wire cap. Capture its actual
        // physical extent and retain/recheck the original descriptor; do not invent a limit.
        let extent = bounded_native_carrier_extent(view, height, usize::MAX).map_err(source)?;
        Ok(Self {
            body: None,
            acquisition: NativeCarrierAcquisition::new_owned(
                view.kura_handle(),
                index,
                hash,
                budget.clone(),
                extent,
            ),
            height,
            hash,
        })
    }
    fn recheck(
        &self,
        view: &(impl StateReadOnly + ?Sized),
        budget: &AllocationBudget,
    ) -> Result<(), ParentServiceError> {
        if !self
            .acquisition
            .matches_owner(view.kura(), self.height, self.hash, budget)
            || view.block_hashes().get(index(self.height)?.get() - 1) != Some(&self.hash)
        {
            return Err(parent_source_failure(
                "parent-service original carrier owner changed",
            ));
        }
        self.acquisition.recheck_original_source().map_err(source)
    }
    fn complete(
        &mut self,
        view: &(impl StateReadOnly + ?Sized),
        budget: &AllocationBudget,
    ) -> Result<&SharedSignedBlock, ParentServiceError> {
        if self.body.is_none() {
            if !self
                .acquisition
                .matches_owner(view.kura(), self.height, self.hash, budget)
                || view.block_hashes().get(index(self.height)?.get() - 1) != Some(&self.hash)
            {
                return Err(parent_source_failure(
                    "parent-service original carrier owner changed",
                ));
            }
            self.body = Some(self.acquisition.complete().map_err(source)?);
        } else {
            self.recheck(view, budget)?;
        }
        Ok(self
            .body
            .as_ref()
            .expect("completed original native carrier"))
    }
}
impl ReceiptRead {
    fn new(
        view: &(impl StateReadOnly + ?Sized),
        height: u64,
        budget: &AllocationBudget,
    ) -> Result<Self, ParentServiceError> {
        Ok(Self {
            frame: AdmittedFrameRead::default(),
            complete: false,
            carrier: Carrier::new(view, height, budget)?,
        })
    }
    fn complete(
        &mut self,
        view: &(impl StateReadOnly + ?Sized),
        budget: &AllocationBudget,
        scope: iroha_data_model::block::consensus::SumeragiRootScope,
    ) -> Result<&CommittedBlock, ParentServiceError> {
        let height = self.carrier.height;
        let block = self.carrier.complete(view, budget)?;
        if !self.complete {
            self.frame
                .initialize(
                    block.clone(),
                    height,
                    scope,
                    &mut EpochValidationScope::new(),
                    budget,
                )
                .map_err(source)?;
            self.complete = true;
        }
        Ok(self.frame.committed())
    }
}
impl ParentServicePreparation {
    /// Retain the actual independently authenticated physical parent acquired by assembly.
    /// The same allocation survives a later authority refusal; this method grants no trust.
    pub(crate) fn retain_assembly_parent(
        &mut self,
        parent: SharedSignedBlock,
    ) -> Result<(), ParentServiceError> {
        if let Some(original) = &self.assembly_parent {
            if !SharedSignedBlock::ptr_eq(original, &parent) {
                return Err(parent_source_failure(
                    "assembly replaced its original physical parent",
                ));
            }
        } else {
            self.assembly_parent = Some(parent);
        }
        Ok(())
    }
    /// Borrow only the existing source after the same cut and physical descriptors recheck.
    pub(crate) fn assembly_parent(
        &self,
        view: &(impl StateReadOnly + ?Sized),
    ) -> Result<Option<SharedSignedBlock>, ParentServiceError> {
        let Some(parent) = &self.assembly_parent else {
            return Ok(None);
        };
        self.require_view(view, parent.header().height().get())?;
        for carrier in [
            self.genesis.as_ref(),
            self.parent.as_ref().map(|read| &read.carrier),
            self.predecessor.as_ref().map(|read| &read.carrier),
        ]
        .into_iter()
        .flatten()
        {
            if carrier.body.is_some() {
                carrier.recheck(view, &view.execution_budget())?;
            }
        }
        Ok(Some(parent.clone()))
    }

    /// Retain original source and complete authority before the worker allocates a disposable
    /// execution overlay or selected-input lease. This method returns no execution authority.
    pub(crate) fn prepare(
        &mut self,
        view: &(impl StateReadOnly + ?Sized),
        parent_height: u64,
    ) -> Result<(), ParentServiceError> {
        if parent_height < 2 {
            return Err(ParentServiceError::Invalid(
                "genesis has no native parent quorum".into(),
            ));
        }
        let budget = view.execution_budget();
        if self.original.is_none() {
            let tip = view.native_execution_tip().ok_or_else(|| {
                parent_source_failure("parent service requires original native execution")
            })?;
            if usize::try_from(tip.height()).ok() != Some(view.height())
                || tip.height() != parent_height
                || view.block_hashes().get(index(parent_height)?.get() - 1)
                    != Some(&tip.iroha_hash())
            {
                return Err(parent_source_failure(
                    "parent service differs from the original native cut",
                ));
            }
            let genesis = *view
                .block_hashes()
                .get(0)
                .ok_or_else(|| parent_source_failure("original genesis is absent"))?;
            let chain_bytes = view.chain_id().as_str().as_bytes();
            let mut chain = [0; iroha_model_base::chain::MAX_CHAIN_ID_BYTES];
            chain[..chain_bytes.len()].copy_from_slice(chain_bytes);
            self.original = Some(Original {
                kura: view.kura_handle(),
                budget: budget.clone(),
                tip,
                network: *view.network_id(),
                chain,
                chain_len: chain_bytes.len(),
                genesis,
            });
        }
        self.require_view(view, parent_height)?;
        if self.genesis.is_none() {
            self.genesis = Some(Carrier::new(view, 1, &budget)?);
        }
        let genesis = self
            .genesis
            .as_mut()
            .expect("original genesis read")
            .complete(view, &budget)?;
        if self.authenticated.is_none() {
            let (_, instance, scope) =
                authenticate_genesis(genesis, view.network_id(), view.chain_id())
                    .map_err(source)?;
            if Some(scope)
                != self
                    .original
                    .as_ref()
                    .map(|original| original.tip.root_scope())
            {
                return Err(parent_source_failure(
                    "signed genesis differs from original native root scope",
                ));
            }
            self.authenticated = Some((instance, scope));
        }
        let scope = self
            .authenticated
            .expect("original genesis authenticated")
            .1;
        if self.parent.is_none() {
            self.parent = Some(ReceiptRead::new(view, parent_height, &budget)?);
        }
        let parent = self
            .parent
            .as_mut()
            .expect("original parent read")
            .complete(view, &budget, scope)?;
        let tip = self.original.as_ref().expect("original native cut").tip;
        crate::state::CanonicalHistorySource::require_native_execution_link(
            parent,
            tip.core_hash(),
            tip.result(),
        )
        .map_err(parent_source_attempt)?;
        let expected_predecessor =
            parent.block().header().prev_block_hash().ok_or_else(|| {
                parent_source_failure("native parent omits its original predecessor")
            })?;
        if view.block_hashes().get(index(parent_height - 1)?.get() - 1)
            != Some(&expected_predecessor)
        {
            return Err(parent_source_failure(
                "parent-service predecessor contradicts original State hash",
            ));
        }
        if self.predecessor.is_none() {
            self.predecessor = Some(ReceiptRead::new(view, parent_height - 1, &budget)?);
        }
        let predecessor = self
            .predecessor
            .as_mut()
            .expect("original predecessor read")
            .complete(view, &budget, scope)?;
        let parent = self
            .parent
            .as_ref()
            .expect("original parent read")
            .frame
            .committed();
        let header = parent
            .header()
            .ok_or_else(|| parent_source_failure("native parent has no consensus header"))?;
        crate::state::CanonicalHistorySource::require_native_execution_link(
            predecessor,
            header.parent_hash,
            header.parent_result,
        )
        .map_err(parent_source_attempt)?;
        if self.authority.is_none() {
            self.authority = Some(
                executed_successor_authority(predecessor, parent, &budget)
                    .map_err(parent_verification_source)?
                    .into_graph(),
            );
        }
        Ok(())
    }

    fn require_view(
        &self,
        view: &(impl StateReadOnly + ?Sized),
        parent_height: u64,
    ) -> Result<(), ParentServiceError> {
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| parent_source_failure("original parent-service preparation absent"))?;
        if !std::ptr::eq(original.kura.as_ref(), view.kura())
            || !original.budget.same_pool(&view.execution_budget())
            || view.native_execution_tip() != Some(original.tip)
            || original.tip.height() != parent_height
            || usize::try_from(parent_height).ok() != Some(view.height())
            || original.network != *view.network_id()
            || &original.chain[..original.chain_len] != view.chain_id().as_str().as_bytes()
            || view.block_hashes().get(0) != Some(&original.genesis)
            || view.block_hashes().get(index(parent_height)?.get() - 1)
                != Some(&original.tip.iroha_hash())
        {
            return Err(parent_source_failure(
                "parent-service retry changed its original source, pool or native cut",
            ));
        }
        Ok(())
    }

    pub(super) fn require_complete(
        &self,
        view: &(impl StateReadOnly + ?Sized),
        parent_height: u64,
    ) -> Result<(), ParentServiceError> {
        self.require_view(view, parent_height)?;
        let original = self.original.as_ref().expect("original cut checked");
        for carrier in [
            self.genesis.as_ref(),
            self.parent.as_ref().map(|read| &read.carrier),
            self.predecessor.as_ref().map(|read| &read.carrier),
        ] {
            carrier
                .ok_or_else(|| {
                    parent_source_failure("original parent-service carrier is incomplete")
                })?
                .recheck(view, &original.budget)?;
        }
        if self.authority.is_none() {
            return Err(parent_source_failure(
                "original parent-service authority is incomplete",
            ));
        }
        Ok(())
    }
    pub(super) fn inputs(
        &self,
    ) -> (
        &CommittedBlock,
        &CommittedBlock,
        AuthorityRef<'_>,
        &HeightConfig,
        PrefixVerifierContext,
    ) {
        let predecessor = self
            .predecessor
            .as_ref()
            .expect("complete predecessor")
            .frame
            .committed();
        let parent = self
            .parent
            .as_ref()
            .expect("complete parent")
            .frame
            .committed();
        let schedule::ScheduledSlot::Ready(scheduled) = &predecessor.commitment().schedule.next
        else {
            unreachable!("original complete authority is ready")
        };
        let authority = self.authority.as_ref().expect("complete authority backing");
        (
            predecessor,
            parent,
            authority.projection(&scheduled.epoch),
            authority.config(),
            PrefixVerifierContext {
                instance: self.authenticated.expect("original signed genesis").0,
            },
        )
    }
}

#[cfg(test)]
impl ParentServicePreparation {
    /// Actual retained allocation identities, used only by caller custody controls.
    pub(crate) fn original_pointers(&self) -> [usize; 5] {
        [
            self.genesis
                .as_ref()
                .and_then(|read| read.body.as_ref())
                .map_or(0, |block| std::ptr::from_ref::<SignedBlock>(block) as usize),
            self.predecessor
                .as_ref()
                .filter(|read| read.complete)
                .map_or(0, |read| {
                    std::ptr::from_ref(read.frame.committed()) as usize
                }),
            self.parent
                .as_ref()
                .filter(|read| read.complete)
                .map_or(0, |read| {
                    std::ptr::from_ref(read.frame.committed()) as usize
                }),
            self.predecessor
                .as_ref()
                .filter(|read| read.complete)
                .map_or(0, |read| {
                    std::ptr::from_ref::<SignedBlock>(read.frame.committed().block()) as usize
                }),
            self.parent
                .as_ref()
                .filter(|read| read.complete)
                .map_or(0, |read| {
                    std::ptr::from_ref::<SignedBlock>(read.frame.committed().block()) as usize
                }),
        ]
    }
}
