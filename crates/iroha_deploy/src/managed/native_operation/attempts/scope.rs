//! Sealed local body-chain evidence; only the custody owner supplies its original namespace proof.
use super::*;
use crate::managed::stream_token_custody::body_history::SnapshotReadPass;
use std::sync::Arc;

mod sealed {
    pub trait EnrollmentScopeEvidence {}
    pub trait BodyReplacementTarget {}
    pub trait SemanticSuccessor {}
    impl EnrollmentScopeEvidence for crate::managed::stream_token_custody::body_history::ScopeEvidence {}
    impl BodyReplacementTarget
        for crate::managed::stream_token_custody::body_history::PlannedBodyReplacement
    {
    }
    impl BodyReplacementTarget
        for crate::managed::stream_token_custody::body_history::ReservedBodySuccessor
    {
    }
    impl SemanticSuccessor
        for crate::managed::stream_token_custody::body_history::ReservedBodySuccessor
    {
    }
}

pub(in crate::managed) struct EnrollmentScopeBinding {
    pub outer_intent: [u8; 32],
    pub body_selection: [u8; 32],
    pub purpose: Purpose,
    pub semantic: [u8; 32],
    pub predecessor_closure: Option<[u8; 32]>,
}
pub(in crate::managed) trait EnrollmentScopeEvidence:
    sealed::EnrollmentScopeEvidence
{
    fn binding(&self) -> &EnrollmentScopeBinding;
    fn root(&self) -> &PrivateDirectory;
    fn operation(&self) -> &PrivateDirectory;
    fn fees(&self) -> &super::super::Fees;
    fn revalidate(&self) -> Result<()>;
    fn with_snapshot_read_pass(
        &self,
        action: &mut dyn FnMut(Option<&SnapshotReadPass<'_>>) -> Result<()>,
    ) -> Result<()>;
    fn revalidate_with_snapshot_read_pass(&self, pass: Option<&SnapshotReadPass<'_>>)
    -> Result<()>;
    fn revalidate_in_tree(
        &self,
        pass: Option<&SnapshotReadPass<'_>>,
        tree: &mut iroha_fs::PrivateReadTreeScope<'_>,
        root_read: Option<&mut GraphRootReadPass<'_, '_>>,
    ) -> Result<()>;
    // Pure membership only; the graph caller retains fresh operation/scope validation.
    fn covers_semantic_original(&self, pass: &SnapshotReadPass<'_>, semantic: [u8; 32]) -> bool;
    fn require_active(&self) -> Result<()>;
}
pub(in crate::managed) trait BodyReplacementTarget:
    sealed::BodyReplacementTarget
{
    fn purpose(&self) -> Purpose;
    fn outer_intent(&self) -> [u8; 32];
    fn predecessor_body(&self) -> [u8; 32];
    fn predecessor_semantic(&self) -> Option<[u8; 32]>;
    fn successor_selection(&self) -> [u8; 32];
    fn fees(&self) -> &super::super::Fees;
    fn validate_target(&self) -> Result<()>;
    fn validate_target_with_snapshot_read_pass(
        &self,
        pass: Option<&SnapshotReadPass<'_>>,
    ) -> Result<()>;
}
pub(in crate::managed) trait SemanticSuccessor:
    sealed::SemanticSuccessor
{
    fn target(&self) -> &dyn BodyReplacementTarget;
    fn revalidate(&self) -> Result<()>;
    fn revalidate_with_snapshot_read_pass(&self, pass: Option<&SnapshotReadPass<'_>>)
    -> Result<()>;
}

struct BodyScopeState {
    evidence: Arc<dyn EnrollmentScopeEvidence>,
    // Moving the verified predecessor keeps its exact local custody attached to the count.
    predecessor: Option<VerifiedUnsignedClosure>,
    root_identity: iroha_fs::FileIdentity,
    operation_identity: iroha_fs::FileIdentity,
}
pub(in crate::managed) struct BodyDispatchScope {
    state: Arc<BodyScopeState>,
}
impl BodyDispatchScope {
    pub(in crate::managed) fn verify(
        evidence: Arc<dyn EnrollmentScopeEvidence>,
        predecessor: Option<VerifiedUnsignedClosure>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<Self> {
        evidence.revalidate_with_snapshot_read_pass(pass.and_then(EnrollmentReadPass::snapshot))?;
        let binding = evidence.binding();
        if !is_enrollment(binding.purpose)
            || binding.outer_intent == [0; 32]
            || binding.body_selection == [0; 32]
            || binding.semantic == [0; 32]
            || binding.predecessor_closure
                != predecessor.as_ref().map(VerifiedUnsignedClosure::digest)
        {
            return Err(invalid(
                "enrollment dispatch scope differs from its verified body chain",
            ));
        }
        evidence.fees().validate()?;
        let root_identity = evidence.root().identity()?;
        let operation_identity = evidence.operation().identity()?;
        if let Some(prior) = &predecessor {
            prior.require_retained_with_pass(pass)?;
            if prior.purpose() != binding.purpose
                || prior.outer_intent() != binding.outer_intent
                || prior.root_identity() != root_identity
                || prior.fees() != evidence.fees()
                || prior.cumulative_reserved_count() > MAX_ATTEMPTS
            {
                return Err(invalid(
                    "enrollment predecessor closure belongs to another original",
                ));
            }
        }
        let value = Self {
            state: Arc::new(BodyScopeState {
                evidence,
                predecessor,
                root_identity,
                operation_identity,
            }),
        };
        value.revalidate_with_pass(pass)?;
        Ok(value)
    }
    fn duplicate(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
    fn revalidate_with_pass(&self, pass: Option<&EnrollmentReadPass<'_>>) -> Result<()> {
        match pass {
            Some(pass) if pass.covers_predecessor(self.state.predecessor.as_ref()) => {
                self.revalidate_local(pass.snapshot())
            }
            _ => self.revalidate(),
        }
    }
    fn revalidate(&self) -> Result<()> {
        self.revalidate_local(None)?;
        if let Some(prior) = &self.state.predecessor {
            retained_graph::validate_predecessor(prior)?;
            self.revalidate_local(None)?;
        }
        Ok(())
    }
    // Does not descend through another History. The graph owner validates every retained
    // predecessor separately while preserving this exact evidence and native handle graph.
    fn revalidate_local(&self, pass: Option<&SnapshotReadPass<'_>>) -> Result<()> {
        self.revalidate_local_in_tree(pass, None, None)
    }
    fn revalidate_local_in_tree(
        &self,
        pass: Option<&SnapshotReadPass<'_>>,
        tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
        root_read: Option<&mut GraphRootReadPass<'_, '_>>,
    ) -> Result<()> {
        let value = &self.state;
        match tree {
            Some(tree) => value.evidence.revalidate_in_tree(pass, tree, root_read)?,
            None => value.evidence.revalidate_with_snapshot_read_pass(pass)?,
        }
        if value.evidence.root().identity()? != value.root_identity
            || value.evidence.operation().identity()? != value.operation_identity
        {
            return Err(invalid("enrollment dispatch scope custody changed"));
        }
        let binding = value.evidence.binding();
        if binding.predecessor_closure
            != value
                .predecessor
                .as_ref()
                .map(VerifiedUnsignedClosure::digest)
        {
            return Err(invalid("enrollment predecessor closure changed"));
        }
        value.evidence.fees().validate()?;
        if let Some(prior) = &value.predecessor {
            if prior.purpose() != binding.purpose
                || prior.outer_intent() != binding.outer_intent
                || prior.root_identity() != value.root_identity
                || prior.fees() != value.evidence.fees()
                || prior.cumulative_reserved_count() > MAX_ATTEMPTS
            {
                return Err(invalid(
                    "enrollment predecessor closure changed its original scope",
                ));
            }
        }
        Ok(())
    }
    fn prior_total(&self) -> usize {
        self.state
            .predecessor
            .as_ref()
            .map_or(0, VerifiedUnsignedClosure::cumulative_reserved_count)
    }
}

pub(in crate::managed) enum HistoryScope {
    FixedBody,
    Enrollment(BodyDispatchScope),
}
impl HistoryScope {
    pub(super) fn retained_copy(&self) -> Self {
        match self {
            Self::FixedBody => Self::FixedBody,
            Self::Enrollment(value) => Self::Enrollment(value.duplicate()),
        }
    }
    pub(super) fn validate(
        &self,
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        match self {
            Self::FixedBody if !is_enrollment(purpose) => {}
            Self::Enrollment(value) if is_enrollment(purpose) => {
                value.revalidate_with_pass(pass)?
            }
            _ => {
                return Err(invalid(
                    "dispatch purpose requires its exact closed body scope",
                ));
            }
        }
        self.validate_binding(operation, purpose, semantic)
    }
    // Private to attempts and its children; callers outside the sole graph owner must use
    // validate above, which includes every predecessor's exact retained history.
    pub(super) fn validate_local(
        &self,
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
        pass: Option<&SnapshotReadPass<'_>>,
        tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
        root_read: Option<&mut GraphRootReadPass<'_, '_>>,
    ) -> Result<()> {
        match self {
            Self::FixedBody if !is_enrollment(purpose) => {}
            Self::Enrollment(value) if is_enrollment(purpose) => {
                value.revalidate_local_in_tree(pass, tree, root_read)?
            }
            _ => {
                return Err(invalid(
                    "dispatch purpose requires its exact closed body scope",
                ));
            }
        }
        self.validate_binding(operation, purpose, semantic)
    }
    // Both entries above revalidate exactly once before joining immutable scope intent to the
    // caller's original operation. This helper never repeats the sealed snapshot traversal.
    fn validate_binding(
        &self,
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
    ) -> Result<()> {
        if let Self::Enrollment(value) = self {
            let evidence = &value.state.evidence;
            let binding = evidence.binding();
            if binding.purpose != purpose
                || binding.semantic != semantic
                || evidence.operation().path() != operation.path()
                || value.state.operation_identity != operation.identity()?
            {
                return Err(invalid(
                    "enrollment scope selected another body or directory",
                ));
            }
        }
        Ok(())
    }
    // Invoked only by the graph-specific capability after fresh validate_local above.
    // Keep the caller's exact operation path, purpose and semantic joined to this evidence;
    // validate_local retains both native identity checks at the local entry and exit.
    pub(super) fn covers_semantic_original(
        &self,
        pass: &SnapshotReadPass<'_>,
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
    ) -> bool {
        let Self::Enrollment(value) = self else {
            return false;
        };
        let evidence = &value.state.evidence;
        evidence.binding().purpose == purpose
            && evidence.binding().semantic == semantic
            && evidence.operation().path() == operation.path()
            && evidence.covers_semantic_original(pass, semantic)
    }
    pub(super) fn with_snapshot_read_pass(
        &self,
        action: &mut dyn FnMut(Option<&SnapshotReadPass<'_>>) -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::FixedBody => action(None),
            Self::Enrollment(value) => value.state.evidence.with_snapshot_read_pass(action),
        }
    }
    pub(super) fn predecessor(&self) -> Option<&VerifiedUnsignedClosure> {
        match self {
            Self::FixedBody => None,
            Self::Enrollment(value) => value.state.predecessor.as_ref(),
        }
    }
    pub(super) fn require_active(&self) -> Result<()> {
        match self {
            Self::FixedBody => Ok(()),
            Self::Enrollment(value) => {
                value.revalidate()?;
                value.state.evidence.require_active()
            }
        }
    }
    pub(super) fn require_fees(&self, fees: &super::super::Fees) -> Result<()> {
        if let Self::Enrollment(value) = self {
            if value.state.evidence.fees() != fees {
                return Err(invalid(
                    "dispatch changed original enrollment fee authorization",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn commitment(&self) -> Result<DispatchScope> {
        Ok(match self {
            Self::FixedBody => DispatchScope::FixedBody,
            Self::Enrollment(value) => {
                let binding = value.state.evidence.binding();
                DispatchScope::Enrollment {
                    outer_intent: binding.outer_intent,
                    body_selection: binding.body_selection,
                    predecessor_closure: binding.predecessor_closure,
                    prior_total: u8::try_from(value.prior_total())
                        .map_err(|_| invalid("enrollment dispatch count overflow"))?,
                }
            }
        })
    }
    pub(super) fn prior_total(&self) -> usize {
        match self {
            Self::FixedBody => 0,
            Self::Enrollment(value) => value.prior_total(),
        }
    }
    pub(super) fn enrollment(&self) -> Result<&dyn EnrollmentScopeEvidence> {
        match self {
            Self::Enrollment(value) => Ok(value.state.evidence.as_ref()),
            Self::FixedBody => Err(invalid(
                "fixed native intent cannot close as an enrollment body",
            )),
        }
    }
}
pub(super) fn is_enrollment(purpose: Purpose) -> bool {
    matches!(
        purpose,
        Purpose::CustodyEnroll(_) | Purpose::CustodyRenewal { .. }
    )
}
