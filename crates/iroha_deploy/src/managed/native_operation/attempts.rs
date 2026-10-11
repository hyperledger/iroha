//! Bounded local dispatch custody shared by the closed generated bootstrap purposes.
//!
//! This module cannot inspect, retire, quote, sign or submit a wallet operation. Concrete owners
//! supply canonical wallet inspections and retirement receipts. Local records never prove native
//! state, successful execution or current authority. The stable native intent is stored once.
#[cfg(test)]
use crate::managed::stream_token_custody::body_history::{
    finish_timing, graph_original_tests, operation_scope_tests,
};

use super::{Terms, encode, invalid, read_optional, require_empty};
use crate::managed::{ManagedBootstrapFailure, Result};
use iroha_crypto::Hash;
use iroha_data_model::sorafs::capacity::ProviderId;
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_wallet::operations::{
    NativePreparationPhase, RetiredNativeRequest, VerifiedNativePreparation,
};
use std::ffi::OsStr;

#[path = "attempts/selection.rs"]
mod selection;
pub(in crate::managed) use selection::{generated, initial};
#[path = "attempts/closure.rs"]
mod closure;
#[path = "attempts/parser_pass.rs"]
mod parser_pass;
#[path = "attempts/retained_graph.rs"]
mod retained_graph;
pub(in crate::managed) use parser_pass::EnrollmentReadPass;
pub(in crate::managed) use retained_graph::GraphRootReadPass;
#[path = "attempts/scope.rs"]
mod scope;
use closure::{ClosurePlan, ClosureRecord};
pub(in crate::managed) use closure::{
    PendingUnsignedClosure, UnsignedClosureVerification, VerifiedUnsignedClosure,
};
pub(in crate::managed) use scope::{
    BodyDispatchScope, BodyReplacementTarget, EnrollmentScopeBinding, EnrollmentScopeEvidence,
    HistoryScope, SemanticSuccessor,
};

pub(in crate::managed) const MAX_ATTEMPTS: usize = 64;
pub(in crate::managed) const MAX_RECORD_BYTES: usize = 16 * 1024;

// The opt-in test capture measures the exact expression once. Ordinary builds evaluate only
// that original expression; the scope owner, arguments and error/return order stay unchanged.
macro_rules! measured_inventory {
    ($phase:ident, $read:expr) => {{
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::$phase);
        $read
    }};
}

/// Fixed paid purposes; a local attempt number is never a native custody sequence or revision.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::Purpose")]
pub(in crate::managed) enum Purpose {
    ReservePolicy,
    CustodyConfigure(ProviderId),
    CustodyEnroll(ProviderId),
    ReserveAccount(ProviderId),
    FundingRequest(ProviderId),
    FundingApproval(ProviderId),
    FundingCredit(ProviderId),
    FundingCapacity(ProviderId),
    ProviderIngest(ProviderId),
    Gateway(ProviderId),
    Reputation,
    /// Existing explicit renewal authorization stays separate from bootstrap replacement.
    CustodyRenewal {
        provider: ProviderId,
        sequence: u64,
    },
}

#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::Origin")]
pub(in crate::managed) enum Origin {
    /// An existing public purpose API authorizes only this one original attempt.
    Explicit,
    /// A retained record binds an epoch; only a live parent capability can authorize its use.
    Generated {
        ordinal: u8,
        epoch: [u8; 32],
        parent_intent: [u8; 32],
    },
}

#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::Authorization")]
struct Authorization {
    ordinal: u8,
    purpose: Purpose,
    semantic: [u8; 32],
    previous: Option<[u8; 32]>,
    origin: Origin,
    terms: Terms,
}

/// An observation timestamp is useful only after the concrete custody owner authenticates the
/// original anchor and current state. No constructor here supplies that native proof.
#[derive(Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::Observation")]
pub(in crate::managed) struct Observation {
    pub(in crate::managed) enrollment_observed_at_unix_ms: Option<u64>,
}
impl Observation {
    pub(in crate::managed) const fn ordinary() -> Self {
        Self {
            enrollment_observed_at_unix_ms: None,
        }
    }
    fn validate(&self, authorization: &Authorization) -> Result<()> {
        let enrollment = matches!(
            authorization.purpose,
            Purpose::CustodyEnroll(_) | Purpose::CustodyRenewal { .. }
        );
        if enrollment != self.enrollment_observed_at_unix_ms.is_some()
            || self.enrollment_observed_at_unix_ms.is_some_and(|time| {
                time == 0 || time >= authorization.terms.signing_deadline_unix_ms
            })
        {
            return Err(invalid(
                "dispatch observation differs from its purpose or original bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::RetirementKind")]
enum RetirementKind {
    Missing,
    Request { request_sha256: String },
}

#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::Retirement")]
struct Retirement {
    authorization: [u8; 32],
    successor: [u8; 32],
    kind: RetirementKind,
}

#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::Commit")]
struct Commit {
    authorization: [u8; 32],
    observation: [u8; 32],
    request_sha256: String,
    previous_retirement: Option<[u8; 32]>,
}

/// The semantic operation retains this commitment outside the attempts subtree before any
/// wallet request is created. Lost committed custody cannot become a new empty authorization.
#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::Dispatch")]
struct Dispatch {
    purpose: Purpose,
    semantic: [u8; 32],
    first: [u8; 32],
    scope: DispatchScope,
    highest: Authorization,
    state: ReservationState,
}
#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::DispatchScope")]
enum DispatchScope {
    FixedBody,
    Enrollment {
        outer_intent: [u8; 32],
        body_selection: [u8; 32],
        predecessor_closure: Option<[u8; 32]>,
        prior_total: u8,
    },
}
#[derive(Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::attempts::ReservationState")]
enum ReservationState {
    Reserved,
    Published,
}

/// A locally validated attempt, not a native proof. Its concrete owner verifies the exact wallet.
pub(in crate::managed) struct Attempt {
    directory: PrivateDirectory,
    authorization: Authorization,
    observation: Option<Observation>,
    commit: Option<Commit>,
    retirement: Option<Retirement>,
}
impl Attempt {
    pub(in crate::managed) fn directory(&self) -> &PrivateDirectory {
        &self.directory
    }
    pub(in crate::managed) fn terms(&self) -> &Terms {
        &self.authorization.terms
    }
    pub(in crate::managed) fn origin(&self) -> &Origin {
        &self.authorization.origin
    }
    pub(in crate::managed) fn digest(&self) -> Result<[u8; 32]> {
        digest(&self.authorization)
    }
    pub(in crate::managed) fn ordinal(&self) -> u8 {
        self.authorization.ordinal
    }
    pub(in crate::managed) fn observation(&self) -> Result<Observation> {
        self.observation
            .ok_or_else(|| ManagedBootstrapFailure::TransitionPending.into())
    }
    pub(in crate::managed) fn is_committed(&self) -> bool {
        self.commit.is_some()
    }
    pub(in crate::managed) fn wallet_path(&self) -> std::path::PathBuf {
        self.directory.path().join("transaction")
    }
    pub(in crate::managed) fn require_selected(&self) -> Result<()> {
        if self.commit.is_none() || self.retirement.is_some() {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        self.verify_authorization()?;
        if read_record::<Commit>(&self.directory, "committed.nrt")? != self.commit
            || read_record::<Retirement>(&self.directory, "retired.nrt")? != self.retirement
            || read_record::<Observation>(&self.directory, "observation.nrt")? != self.observation
        {
            return Err(invalid("selected dispatch custody changed"));
        }
        Ok(())
    }
    fn verify_authorization(&self) -> Result<()> {
        // The canonical read begins native custody checks and rechecks optional absence.
        if read_record::<Authorization>(&self.directory, "authorization.nrt")?.as_ref()
            != Some(&self.authorization)
        {
            return Err(invalid(
                "original dispatch authorization was lost or changed",
            ));
        }
        Ok(())
    }
    fn verify_authorization_in_scope(
        &self,
        reader: &mut iroha_fs::PrivateReadScope<'_>,
    ) -> Result<()> {
        if read_record_in_scope::<Authorization>(reader, "authorization.nrt")?.as_ref()
            != Some(&self.authorization)
        {
            return Err(invalid(
                "original dispatch authorization was lost or changed",
            ));
        }
        Ok(())
    }
    fn validate_inventory(&self, names: &[std::ffi::OsString], reserved: bool) -> Result<()> {
        if reserved
            && (names.len() != 1 || names.first().is_none_or(|name| name != "authorization.nrt"))
        {
            return Err(invalid(
                "reserved dispatch contains effects before publication",
            ));
        }
        let native = names
            .iter()
            .any(|name| name == "replay.nrt" || name == "carrier.nrt");
        if self.commit.is_none() && native {
            return Err(invalid(
                "uncommitted dispatch contains native execution material",
            ));
        }
        if self.retirement.is_some() && native {
            return Err(invalid(
                "retired dispatch contains changed or execution material",
            ));
        }
        Ok(())
    }
    fn retain_observation(&self, observation: Observation) -> Result<()> {
        self.verify_authorization()?;
        observation.validate(&self.authorization)?;
        write_record(&self.directory, "observation.nrt", &observation)
    }
}

/// Read-only bounded metadata. No arbitrary filename can select a native head or grant signing.
pub(in crate::managed) struct History {
    operation: PrivateDirectory,
    dispatch: Option<Dispatch>,
    root: Option<PrivateDirectory>,
    attempts: Vec<Attempt>,
    empty_tail: bool,
    scope: HistoryScope,
    closing: Option<ClosurePlan>,
    closed: Option<ClosureRecord>,
    cumulative_reserved: usize,
    purpose: Purpose,
    semantic: [u8; 32],
}

/// Typed native intent plus its one selected paid attempt. This is an in-memory view, not a
/// second serialized layout or a constructor for authenticated transaction history.
pub(in crate::managed) struct Selected<I> {
    intent: I,
    history: History,
    pub(in crate::managed) terms: Terms,
}
impl<I> std::ops::Deref for Selected<I> {
    type Target = I;
    fn deref(&self) -> &I {
        &self.intent
    }
}
impl<I> Selected<I> {
    pub(in crate::managed) fn from_history(intent: I, history: History) -> Result<Self> {
        let terms = history
            .selected()?
            .ok_or(ManagedBootstrapFailure::TransitionPending)?
            .terms()
            .clone();
        Ok(Self {
            intent,
            history,
            terms,
        })
    }
    pub(in crate::managed) fn attempt(&self) -> &Attempt {
        // Construction requires a selected committed last attempt; the private history never
        // mutates. Callers still revalidate filesystem custody around their native operations.
        self.history
            .attempts
            .last()
            .expect("selected dispatch history is nonempty")
    }
    pub(in crate::managed) fn directory(&self) -> &PrivateDirectory {
        self.attempt().directory()
    }
    pub(in crate::managed) fn observation(&self) -> Result<Observation> {
        self.attempt().observation()
    }
    pub(in crate::managed) fn verify_wallets(
        &self,
        inspect: impl FnMut(&I, &Attempt) -> Result<VerifiedNativePreparation>,
    ) -> Result<()> {
        let mut inspect = inspect;
        self.history
            .verify_wallets(|attempt| inspect(&self.intent, attempt))
    }
}
impl History {
    pub(in crate::managed) fn read(
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
        scope: &HistoryScope,
    ) -> Result<Self> {
        Self::read_with_handles(operation, purpose, semantic, scope, None, None)
    }

    // The opaque graph lends only native handles. Every record and the supplied fresh scope
    // pass through the ordinary parser. A new body may have no member in the retained graph.
    pub(in crate::managed) fn read_retained(
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
        scope: &HistoryScope,
        retained: &History,
    ) -> Result<Self> {
        Self::read_retained_with_pass(operation, purpose, semantic, scope, retained, None)
    }

    pub(in crate::managed) fn read_with_pass(
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
        scope: &HistoryScope,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<Self> {
        Self::read_with_handles(operation, purpose, semantic, scope, None, pass)
    }

    pub(in crate::managed) fn read_retained_with_pass(
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
        scope: &HistoryScope,
        retained: &History,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<Self> {
        let covered = pass.is_some_and(|pass| pass.covers_retained(retained));
        if !covered {
            retained.revalidate_retained_handles()?;
        }
        let mut current = Some(retained);
        let mut matched = None;
        let mut count = 0usize;
        while let Some(history) = current {
            count += 1;
            if count > MAX_ATTEMPTS {
                return Err(invalid("retained dispatch graph exceeds its body bound"));
            }
            if history.operation.path() == operation.path() {
                if matched.is_some()
                    || history.purpose != purpose
                    || history.semantic != semantic
                    || history.operation.identity()? != operation.identity()?
                {
                    return Err(invalid("retained dispatch belongs to another original"));
                }
                matched = Some(history);
            }
            current = history
                .scope
                .predecessor()
                .map(VerifiedUnsignedClosure::retained_history);
        }
        let current = Self::read_with_handles(operation, purpose, semantic, scope, matched, pass)?;
        if !covered {
            retained.revalidate_retained_handles()?;
        }
        Ok(current)
    }

    fn read_with_handles(
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
        scope: &HistoryScope,
        retained: Option<&History>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<Self> {
        if let Some(prior) = retained {
            prior.revalidate_handles()?;
            if prior.operation.path() != operation.path()
                || prior.operation.identity()? != operation.identity()?
                || prior.purpose != purpose
                || prior.semantic != semantic
                || prior.scope.commitment()? != scope.commitment()?
            {
                return Err(invalid("retained dispatch belongs to another original"));
            }
        }
        let current = Self::parse(operation, purpose, semantic, scope, retained, pass)?;
        if let Some(prior) = retained {
            prior.revalidate_handles()?;
            if (prior.root.is_some()
                && prior
                    .root
                    .as_ref()
                    .map(PrivateDirectory::identity)
                    .transpose()?
                    != current
                        .root
                        .as_ref()
                        .map(PrivateDirectory::identity)
                        .transpose()?)
                || current.attempts.len() < prior.attempts.len()
            {
                return Err(invalid(
                    "dispatch custody changed across its local transition",
                ));
            }
            for (before, after) in prior.attempts.iter().zip(&current.attempts) {
                after.directory.revalidate()?;
                if before.directory.identity()? != after.directory.identity()?
                    || before.authorization != after.authorization
                    || before.observation.is_some() && before.observation != after.observation
                    || before.commit.is_some() && before.commit != after.commit
                    || before.retirement.is_some() && before.retirement != after.retirement
                {
                    return Err(invalid(
                        "dispatch attempt custody changed across its local transition",
                    ));
                }
            }
        }
        if let Some(prior) = retained {
            if prior.closing.is_some() && prior.closing != current.closing
                || prior.closed.is_some() && prior.closed != current.closed
            {
                return Err(invalid("retained dispatch closure was lost or changed"));
            }
            if let Some(before) = &prior.dispatch {
                let after = current
                    .dispatch
                    .as_ref()
                    .ok_or_else(|| invalid("retained dispatch high-water was lost"))?;
                let selected = current
                    .attempts
                    .get(usize::from(before.highest.ordinal) - 1)
                    .map(|attempt| &attempt.authorization)
                    .or_else(|| {
                        (after.highest.ordinal == before.highest.ordinal).then_some(&after.highest)
                    });
                if before.first != after.first
                    || before.scope != after.scope
                    || selected != Some(&before.highest)
                    || before.highest.ordinal > after.highest.ordinal
                    || before.state == ReservationState::Published
                        && before.highest.ordinal == after.highest.ordinal
                        && after.state != ReservationState::Published
                {
                    return Err(invalid("retained dispatch high-water regressed or changed"));
                }
            }
        }
        current.revalidate_handles()?;
        Ok(current)
    }

    fn revalidate_parser_handles(&self, pass: Option<&EnrollmentReadPass<'_>>) -> Result<()> {
        match pass {
            Some(pass) => pass.revalidate_handles(self),
            None => self.revalidate_retained_handles(),
        }
    }

    // Directory custody only: old metadata can legitimately differ after the canonical writer.
    // Fresh record/scope verification belongs exclusively to the parser, never this traversal.
    pub(in crate::managed) fn revalidate_retained_handles(&self) -> Result<()> {
        // There is no common predecessor ancestry to share on the single-body path.
        // Inherited decode owners retain the original physical handle-check recipe.
        if self.scope.predecessor().is_none() || norito::core::decode_limits_active() {
            return self.revalidate_retained_handles_in_tree(None);
        }
        // This census reads handles only and closes before its caller can parse records,
        // inspect a wallet or perform an effect. Every separate census stays separate.
        retained_graph::with_native_read_tree(self, |tree| {
            #[cfg(test)]
            retained_handle_census_tests::record_tree_bracket(tree.is_some());
            self.revalidate_retained_handles_in_tree(tree)
        })
    }

    // A caller-owned BodyHistory bracket can share its original ancestor across sibling
    // operations. This carries handles only, never a source, record or authority verdict.
    pub(in crate::managed) fn revalidate_retained_handles_in_tree(
        &self,
        mut tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
    ) -> Result<()> {
        let mut current = Some(self);
        let mut count = 0usize;
        while let Some(history) = current {
            count += 1;
            if count > MAX_ATTEMPTS {
                return Err(invalid("retained dispatch graph exceeds its body bound"));
            }
            #[cfg(test)]
            retained_handle_census_tests::record_history(history);
            match tree.as_deref_mut() {
                Some(tree) => history.revalidate_handles_in_tree(tree)?,
                None => history.revalidate_handles()?,
            }
            current = history
                .scope
                .predecessor()
                .map(VerifiedUnsignedClosure::retained_history);
        }
        Ok(())
    }

    fn revalidate_handles(&self) -> Result<()> {
        #[cfg(test)]
        retained_handle_census_tests::record_full_operation();
        // Entry authenticates the original operation first; exit closes every Result.
        // No record read, native observation, signing or mutation runs in this bracket.
        self.operation
            .read_tree_scope(|tree| self.revalidate_descendant_handles_in_tree(tree))
    }

    fn revalidate_handles_in_tree(
        &self,
        tree: &mut iroha_fs::PrivateReadTreeScope<'_>,
    ) -> Result<()> {
        #[cfg(test)]
        retained_handle_census_tests::record_tree_operation();
        tree.revalidate_directory(&self.operation)?;
        // Existing callers can already lend a tree while a decoder is active. Preserve
        // their original native observation recipe as well as the standalone fallback.
        if norito::core::decode_limits_active() {
            return self.revalidate_descendant_handles_in_tree(tree);
        }
        let result = self.revalidate_descendant_handles_in_tree(tree);
        #[cfg(test)]
        let result = result.and_then(|()| retained_handle_census_tests::after_descendants());
        // Preserve the operation's closing observation after every descendant and every
        // ordinary result. Its refusal takes precedence before the outer root also closes.
        #[cfg(test)]
        retained_handle_census_tests::record_operation_exit();
        tree.revalidate_directory(&self.operation)?;
        result
    }

    fn revalidate_descendant_handles_in_tree(
        &self,
        tree: &mut iroha_fs::PrivateReadTreeScope<'_>,
    ) -> Result<()> {
        if let Some(root) = &self.root {
            #[cfg(test)]
            retained_handle_census_tests::record_attempt_root(root);
            tree.revalidate_directory(root)?;
        }
        for attempt in &self.attempts {
            #[cfg(test)]
            retained_handle_census_tests::record_attempt(&attempt.directory);
            tree.revalidate_directory(&attempt.directory)?;
        }
        Ok(())
    }

    fn parse(
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
        scope: &HistoryScope,
        retained: Option<&History>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<Self> {
        #[cfg(test)]
        closure::record_history_parse_for_test();
        scope.validate(operation, purpose, semantic, pass)?;
        // The inventory begins and ends with fresh native directory checks.
        operation_inventory(operation, purpose)?;
        require_semantic_original(operation, semantic)?;
        let retained_operation = match retained {
            Some(prior) => prior.operation.retain()?,
            None => operation.retain()?,
        };
        if retained_operation.identity()? != operation.identity()? {
            return Err(invalid("dispatch operation custody changed"));
        }
        let (dispatch, cumulative_reserved, closing, closed) = operation.read_scope(|reader| {
            let dispatch: Option<Dispatch> = read_record_in_scope(reader, "dispatch.nrt")?;
            if let Some(value) = &dispatch {
                value.highest.terms.validate()?;
                validate_origin(&value.highest.origin)?;
                scope.require_fees(&value.highest.terms.fees)?;
                if value.purpose != purpose
                    || value.semantic != semantic
                    || value.scope != scope.commitment()?
                    || value.highest.purpose != purpose
                    || value.highest.semantic != semantic
                    || value.highest.ordinal == 0
                    || scope
                        .prior_total()
                        .checked_add(usize::from(value.highest.ordinal))
                        .is_none_or(|n| n > MAX_ATTEMPTS)
                    || value.first == [0; 32]
                    || (value.highest.ordinal == 1
                        && (value.highest.previous.is_some()
                            || value.first != digest(&value.highest)?))
                {
                    return Err(invalid(
                        "dispatch high-water differs from its original scope",
                    ));
                }
            }
            let cumulative_reserved = scope
                .prior_total()
                .checked_add(
                    dispatch
                        .as_ref()
                        .map_or(0, |value| usize::from(value.highest.ordinal)),
                )
                .filter(|count| *count <= MAX_ATTEMPTS)
                .ok_or_else(|| invalid("body dispatch count exceeds its cumulative bound"))?;
            let closing: Option<ClosurePlan> = read_record_in_scope(reader, "closing.nrt")?;
            let closed: Option<ClosureRecord> = read_record_in_scope(reader, "closed.nrt")?;
            Ok::<_, crate::managed::Error>((dispatch, cumulative_reserved, closing, closed))
        })?;
        let root = match retained.and_then(|prior| prior.root.as_ref()) {
            Some(root) => root.retain().map(Some),
            None => operation.open_child_optional("attempts"),
        };
        let root = match root {
            Ok(Some(value)) => value,
            Ok(None) => {
                if dispatch.as_ref().is_some_and(|value| {
                    value.state != ReservationState::Reserved || value.highest.ordinal != 1
                }) {
                    return Err(invalid("retained dispatch lost its attempts custody"));
                }
                let empty_tail = dispatch.is_some();
                let value = Self {
                    operation: retained_operation,
                    dispatch,
                    root: None,
                    attempts: Vec::new(),
                    empty_tail,
                    scope: scope.retained_copy(),
                    closing,
                    closed,
                    cumulative_reserved,
                    purpose,
                    semantic,
                };
                value.validate_closure_records()?;
                return Ok(value);
            }
            Err(error) => return Err(error.into()),
        };
        let names = measured_inventory!(AttemptInventory, root.entries(MAX_ATTEMPTS))?;
        if dispatch.is_none() {
            return Err(invalid("attempt custody lost its dispatch high-water"));
        }
        // These scratch hashes belong only to this parse. Each owned Authorization is
        // immutable after its fresh decode; no source, scope or wallet verdict is retained.
        fn row_digest(attempt: &Attempt, cached: &mut Option<[u8; 32]>) -> Result<[u8; 32]> {
            #[cfg(test)]
            tests::parse_digest_tests::digest_requested();
            if let Some(value) = *cached {
                return Ok(value);
            }
            let value = attempt.digest()?;
            #[cfg(test)]
            tests::parse_digest_tests::digest_computed(attempt.ordinal());
            *cached = Some(value);
            Ok(value)
        }
        let mut first_digest = None;
        let mut last_digest = None;
        let mut attempts: Vec<Attempt> = Vec::with_capacity(names.len());
        let mut empty_tail = false;
        // One fresh attempts-root transaction shares only its exact retained native prefix.
        // Every row retains its original owner, inventory, lazy record/codec order and semantic
        // checks; nonshared owners use full checks. The exit closes every ordinary loop result.
        root.read_tree_scope(|tree| {
            for (index, name) in names.iter().enumerate() {
                if name != OsStr::new(&format!("{:04}", index + 1)) {
                    return Err(invalid(
                        "dispatch attempt inventory has a gap or foreign name",
                    ));
                }
                let directory = match retained.and_then(|prior| prior.attempts.get(index)) {
                    Some(attempt) => {
                        if attempt.directory.path() != root.path().join(name) {
                            return Err(invalid("retained dispatch row belongs to another path"));
                        }
                        attempt.directory.retain()?
                    }
                    None => root.open_child(name)?,
                };
                let (inventory, row) = tree.read_scope(&directory, |reader| {
                    let inventory = checked_attempt_inventory(measured_inventory!(AttemptScopedInventory, reader.entries(7))?)?;
                    let Some(authorization): Option<Authorization> =
                        read_record_in_scope(reader, "authorization.nrt")?
                    else {
                        if index + 1 != names.len()
                            || !inventory.is_empty()
                            || !dispatch.as_ref().is_some_and(|value| {
                                value.state == ReservationState::Reserved
                                    && usize::from(value.highest.ordinal) == index + 1
                            })
                        {
                            return Err(invalid(
                                "dispatch material exists without its authorization",
                            ));
                        }
                        return Ok((inventory, None));
                    };
                    authorization.terms.validate()?;
                    scope.require_fees(&authorization.terms.fees)?;
                    validate_origin(&authorization.origin)?;
                    let previous = attempts
                        .last()
                        .map(|attempt| row_digest(attempt, &mut last_digest))
                        .transpose()?;
                    if attempts.len() == 1 {
                        first_digest = last_digest;
                    }
                    if usize::from(authorization.ordinal) != index + 1
                        || authorization.purpose != purpose
                        || authorization.semantic != semantic
                        || authorization.previous != previous
                    {
                        return Err(invalid(
                            "dispatch authorization changed its original purpose, intent or predecessor",
                        ));
                    }
                    if let Some(prior) = attempts.last() {
                        validate_successor(&prior.authorization, &authorization)?;
                    }
                    let observation: Option<Observation> =
                        read_record_in_scope(reader, "observation.nrt")?;
                    if let Some(observation) = observation {
                        observation.validate(&authorization)?;
                    }
                    let commit: Option<Commit> = read_record_in_scope(reader, "committed.nrt")?;
                    let retirement: Option<Retirement> = read_record_in_scope(reader, "retired.nrt")?;
                    Ok::<_, crate::managed::Error>((
                        inventory,
                        Some((authorization, observation, commit, retirement)),
                    ))
                })?;
                let Some((authorization, observation, commit, retirement)) = row else {
                    empty_tail = true;
                    continue;
                };
                let attempt = Attempt {
                    directory,
                    authorization,
                    observation,
                    commit,
                    retirement,
                };
                attempt.validate_inventory(
                    &inventory,
                    dispatch.as_ref().is_some_and(|value| {
                        value.state == ReservationState::Reserved
                            && usize::from(value.highest.ordinal) == index + 1
                    }),
                )?;
                let mut current_digest = None;
                if let Some(commit) = &attempt.commit {
                    let observed = attempt
                        .observation
                        .ok_or_else(|| invalid("committed dispatch lost its original observation"))?;
                    let prior_retirement = attempts
                        .last()
                        .map(|prior| {
                            prior
                                .retirement
                                .as_ref()
                                .ok_or_else(|| invalid("dispatch predecessor was not retired"))
                        })
                        .transpose()?;
                    if !valid_sha256(&commit.request_sha256)
                        || commit.authorization != row_digest(&attempt, &mut current_digest)?
                        || commit.observation != digest(&observed)?
                        || commit.previous_retirement != prior_retirement.map(digest).transpose()?
                    {
                        return Err(invalid("dispatch commit differs from original custody"));
                    }
                }
                if let Some(retirement) = &attempt.retirement {
                    if retirement.authorization != row_digest(&attempt, &mut current_digest)?
                        || retirement.successor == [0; 32]
                        || matches!(&retirement.kind, RetirementKind::Request { request_sha256 } if !valid_sha256(request_sha256))
                    {
                        return Err(invalid(
                            "retired dispatch contains changed or execution material",
                        ));
                    }
                }
                if let Some(prior) = attempts.last() {
                    if let Some(retirement) = &prior.retirement {
                        if retirement.successor != row_digest(&attempt, &mut current_digest)? {
                            return Err(invalid("unsigned retirement selected another successor"));
                        }
                    } else if index + 1 != names.len() || attempt.commit.is_some() {
                        return Err(invalid(
                            "dispatch chain has an unretired interior predecessor",
                        ));
                    }
                }
                if attempts.is_empty() {
                    first_digest = current_digest;
                }
                last_digest = current_digest;
                attempts.push(attempt);
            }
            Ok::<_, crate::managed::Error>(())
        })?;
        if let Some(last) = attempts.last() {
            if let Some(retirement) = &last.retirement {
                if !dispatch.as_ref().is_some_and(|value| {
                    value.state == ReservationState::Reserved
                        && value.highest.previous == row_digest(last, &mut last_digest).ok()
                        && digest(&value.highest).ok() == Some(retirement.successor)
                }) {
                    return Err(invalid("unsigned retirement lost its reserved successor"));
                }
            }
        }
        if measured_inventory!(AttemptInventory, root.entries(MAX_ATTEMPTS))? != names {
            return Err(invalid("dispatch inventory changed during inspection"));
        }
        let retained = dispatch
            .as_ref()
            .ok_or_else(|| invalid("dispatch anchor absent"))?;
        let count = usize::from(retained.highest.ordinal);
        if names.len() > count
            || attempts.len() > count
            || attempts
                .first()
                .map(|attempt| {
                    if attempts.len() == 1 {
                        row_digest(attempt, &mut last_digest)
                    } else {
                        row_digest(attempt, &mut first_digest)
                    }
                })
                .transpose()?
                .unwrap_or(digest(&retained.highest)?)
                != retained.first
        {
            return Err(invalid(
                "dispatch root differs from its retained authorization chain",
            ));
        }
        if attempts.len() == count {
            if attempts.last().map(|a| &a.authorization) != Some(&retained.highest) {
                return Err(invalid("highest dispatch authorization changed"));
            }
        } else {
            if retained.state != ReservationState::Reserved
                || attempts.len() + 1 != count
                || retained.highest.previous
                    != attempts
                        .last()
                        .map(|attempt| row_digest(attempt, &mut last_digest))
                        .transpose()?
            {
                return Err(invalid("published dispatch suffix was lost"));
            }
            if let Some(prior) = attempts.last() {
                validate_successor(&prior.authorization, &retained.highest)?;
            }
            empty_tail = true;
        }
        if retained.state == ReservationState::Published && (empty_tail || names.len() != count) {
            return Err(invalid("published dispatch custody is incomplete"));
        }
        operation.revalidate()?;
        let value = Self {
            operation: retained_operation,
            dispatch,
            root: Some(root),
            attempts,
            empty_tail,
            scope: scope.retained_copy(),
            closing,
            closed,
            cumulative_reserved,
            purpose,
            semantic,
        };
        value.validate_closure_records()?;
        Ok(value)
    }

    #[cfg(test)]
    pub(in crate::managed) fn test_enrollment_evidence(
        &self,
    ) -> Result<&dyn EnrollmentScopeEvidence> {
        self.scope.enrollment()
    }

    /// Inspect every retained wallet through the concrete canonical purpose owner. The closure
    /// cannot substitute a decoded DTO for the opaque wallet result.
    pub(in crate::managed) fn verify_wallets(
        &self,
        inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
    ) -> Result<()> {
        self.verify_wallets_with_pass(inspect, None)
    }
    pub(in crate::managed) fn verify_wallets_with_pass(
        &self,
        inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        if self.closing.is_some() || self.closed.is_some() {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        self.verify_wallets_inner(inspect, None, pass)
    }
    fn verify_wallets_inner(
        &self,
        mut inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
        closing: Option<&ClosurePlan>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        self.require_current_with_pass(pass)?;
        if closing != self.closing.as_ref() {
            return Err(invalid("wallet verifier has another unsigned closing plan"));
        }
        for (index, attempt) in self.attempts.iter().enumerate() {
            if attempt.observation.is_none() {
                if measured_inventory!(AttemptInventory, attempt.directory.entries(7))?
                    .iter()
                    .any(|name| name == "transaction")
                {
                    return Err(invalid(
                        "dispatch wallet exists without a selected observation",
                    ));
                }
                if let Some(retirement) = &attempt.retirement {
                    if retirement.kind != RetirementKind::Missing {
                        return Err(invalid("unobserved dispatch has a request retirement"));
                    }
                }
                continue;
            }
            let preparation = inspect(attempt)?;
            if self.empty_tail
                && index + 1 == self.attempts.len()
                && matches!(
                    preparation.phase(),
                    NativePreparationPhase::PayloadRetained | NativePreparationPhase::Signed
                )
            {
                return Err(invalid(
                    "unfinished successor directory cannot replace paid custody",
                ));
            }
            if let Some(commit) = &attempt.commit {
                if preparation.request_sha256() != Some(commit.request_sha256.as_str()) {
                    return Err(invalid(
                        "committed dispatch lost or changed its original wallet request",
                    ));
                }
            } else if matches!(
                preparation.phase(),
                NativePreparationPhase::PayloadRetained | NativePreparationPhase::Signed
            ) {
                return Err(invalid(
                    "uncommitted dispatch contains a paid payload or signature",
                ));
            }
            if index + 1 == self.attempts.len() {
                if let Some(plan) = closing {
                    plan.validate_tail_wallet(attempt, &preparation)?;
                }
            }
            match (&attempt.retirement, preparation.phase()) {
                (
                    Some(Retirement {
                        kind: RetirementKind::Missing,
                        ..
                    }),
                    NativePreparationPhase::Missing,
                ) => {}
                (
                    Some(Retirement {
                        kind: RetirementKind::Request { request_sha256 },
                        ..
                    }),
                    NativePreparationPhase::Retired,
                ) if preparation.request_sha256() == Some(request_sha256.as_str()) => {}
                (Some(_), _) => {
                    return Err(invalid(
                        "retired dispatch wallet no longer proves its exact unsigned retirement",
                    ));
                }
                (None, NativePreparationPhase::Retired)
                    if index + 1 == self.attempts.len()
                        && closing
                            .map(|plan| plan.permits_retired_tail(attempt, &preparation))
                            .transpose()?
                            .unwrap_or(false) => {}
                (None, NativePreparationPhase::Retired)
                    if index + 1 == self.attempts.len() - 1
                        && self
                            .attempts
                            .last()
                            .is_some_and(|next| !next.is_committed()) => {}
                (None, NativePreparationPhase::Retired) => {
                    return Err(invalid("retired wallet has no exact reserved successor"));
                }
                (None, _) if index + 1 == self.attempts.len() => {}
                (None, NativePreparationPhase::Missing | NativePreparationPhase::RequestOnly)
                    if index + 2 == self.attempts.len()
                        && self
                            .attempts
                            .last()
                            .is_some_and(|next| !next.is_committed()) => {}
                (None, _) => {
                    return Err(invalid(
                        "a reserved successor cannot replace retained paid material",
                    ));
                }
            }
        }
        self.require_current_with_pass(pass)?;
        Ok(())
    }

    fn require_current(&self) -> Result<()> {
        retained_graph::validate(self)
    }
    fn require_current_with_pass(&self, pass: Option<&EnrollmentReadPass<'_>>) -> Result<()> {
        match pass {
            Some(pass) => pass.validate(self),
            None => self.require_current(),
        }
    }
    pub(in crate::managed) fn close_parser_read(&self) -> Result<()> {
        self.require_current()
    }

    // The parser already owns predecessor coverage and its separate full-graph exit. This
    // bracket shares only native ancestry inside one local census; every original record,
    // codec, inventory and scope check still runs before it closes on every ordinary result.
    fn require_current_local(
        &self,
        pass: Option<&crate::managed::stream_token_custody::body_history::SnapshotReadPass<'_>>,
    ) -> Result<()> {
        retained_graph::with_native_read_tree(self, |tree| {
            self.require_current_local_in_tree(pass, tree, None, None)
        })
    }

    fn require_current_local_in_tree(
        &self,
        pass: Option<&crate::managed::stream_token_custody::body_history::SnapshotReadPass<'_>>,
        mut tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
        originals: Option<&retained_graph::OriginalReadPass<'_, '_>>,
        mut root_read: Option<&mut GraphRootReadPass<'_, '_>>,
    ) -> Result<()> {
        // An inherited decoder always retains the original physical read/allocation recipe,
        // even if a caller entered this native bracket before installing its decode owner.
        if norito::core::decode_limits_active() {
            tree = None;
        }
        #[cfg(test)]
        retained_graph::record_validation_visit(self)?;
        #[cfg(test)]
        retained_graph::record_native_tree_visit(tree.is_some());
        // The original identity-aware handles remain live. Re-read their bounded canonical
        // records one at a time instead of retaining another complete directory graph.
        // Only the callback-free complete graph lends this bracket to scope evidence.
        // Parser-local and standalone censuses retain their independent source recipe.
        self.scope.validate_local(
            &self.operation,
            self.purpose,
            self.semantic,
            pass,
            if originals.is_some() {
                tree.as_deref_mut()
            } else {
                None
            },
            root_read.as_deref_mut(),
        )?;
        // The inventory begins and ends with fresh native directory checks.
        let operation_names = self.require_operation_entry(tree.as_deref_mut(), originals)?;
        match &self.root {
            None => {
                if operation_names.iter().any(|name| name == "attempts") {
                    return Err(invalid(
                        "dispatch inventory changed during native operation",
                    ));
                }
            }
            Some(root) => {
                // entries brackets its actual census with native custody checks.
                let names = directory_entries_in_tree(root, MAX_ATTEMPTS, tree.as_deref_mut())?;
                if names.len() < self.attempts.len()
                    || names.len() > self.attempts.len() + usize::from(self.empty_tail)
                    || names
                        .iter()
                        .enumerate()
                        .any(|(index, name)| name != OsStr::new(&format!("{:04}", index + 1)))
                {
                    return Err(invalid(
                        "dispatch inventory changed during native operation",
                    ));
                }
                let inspect_attempts = |tree: &mut iroha_fs::PrivateReadTreeScope<'_>| {
                    for attempt in &self.attempts {
                        tree.read_scope(&attempt.directory, |reader| {
                            // Both native censuses and all lazy record reads share one closed
                            // suffix bracket; persistent exit custody overrides every result.
                            let inventory = checked_attempt_inventory(measured_inventory!(
                                AttemptScopedInventory,
                                reader.entries(7)
                            )?)?;
                            attempt.validate_inventory(
                                &inventory,
                                self.dispatch.as_ref().is_some_and(|value| {
                                    value.state == ReservationState::Reserved
                                        && value.highest.ordinal == attempt.ordinal()
                                }),
                            )?;
                            attempt.verify_authorization_in_scope(reader)?;
                            if read_record_in_scope::<Observation>(reader, "observation.nrt")?
                                != attempt.observation
                                || read_record_in_scope::<Commit>(reader, "committed.nrt")?
                                    != attempt.commit
                                || read_record_in_scope::<Retirement>(reader, "retired.nrt")?
                                    != attempt.retirement
                            {
                                return Err(invalid(
                                    "retained dispatch metadata changed during native operation",
                                ));
                            }
                            if checked_attempt_inventory(measured_inventory!(
                                AttemptScopedInventory,
                                reader.entries(7)
                            )?)? != inventory
                            {
                                return Err(invalid(
                                    "retained dispatch metadata changed during native operation",
                                ));
                            }
                            Ok::<_, crate::managed::Error>(())
                        })?;
                    }
                    Ok::<_, crate::managed::Error>(())
                };
                match tree.as_deref_mut() {
                    Some(tree) => inspect_attempts(tree)?,
                    None => root.read_tree_scope(inspect_attempts)?,
                }
                // A Reserved prefix may have its last empty directory but no authorization.
                // It is inspected transiently; Published custody can never use this branch.
                if names.len() > self.attempts.len() {
                    let tail = root.open_child(&names[self.attempts.len()])?;
                    if !directory_entries_in_tree(&tail, 1, tree.as_deref_mut())?.is_empty() {
                        return Err(invalid("reserved dispatch empty tail changed"));
                    }
                    revalidate_directory_in_tree(&tail, tree.as_deref_mut())?;
                }
                if directory_entries_in_tree(root, MAX_ATTEMPTS, tree.as_deref_mut())? != names {
                    return Err(invalid("dispatch inventory changed during inspection"));
                }
                revalidate_directory_in_tree(root, tree.as_deref_mut())?;
            }
        }
        if self.require_operation_exit(tree.as_deref_mut(), originals)? != operation_names {
            return Err(invalid(
                "dispatch operation inventory changed during inspection",
            ));
        }
        revalidate_directory_in_tree(&self.operation, tree.as_deref_mut())?;
        self.scope.validate_local(
            &self.operation,
            self.purpose,
            self.semantic,
            pass,
            if originals.is_some() { tree } else { None },
            root_read,
        )
    }

    // Keep original native owners live through the sole fresh parser; retain shares their
    // Files rather than opening a second complete graph before the old value can drop.
    fn reread(self) -> Result<Self> {
        #[cfg(test)]
        let _closure_timing =
            finish_timing::phase_in_closure(finish_timing::Phase::ClosureRetainedRead);
        Self::read_retained(
            &self.operation,
            self.purpose,
            self.semantic,
            &self.scope,
            &self,
        )
    }

    // Only adjacent internal reads share a suffix bracket. The attempt traversal, full
    // graph/snapshot exits and effectful callers retain all of their independent fences.
    // Intermediate suffix observations consolidate under iroha_fs's read_scope contract.
    fn require_operation_entry(
        &self,
        mut tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
        originals: Option<&retained_graph::OriginalReadPass<'_, '_>>,
    ) -> Result<Vec<std::ffi::OsString>> {
        if reuse_operation_scope()
            && let Some(tree) = tree.as_deref_mut()
        {
            #[cfg(test)]
            operation_scope_tests::bracket();
            return tree.read_scope(&self.operation, |reader| {
                let names = operation_inventory_in_scope(reader, self.purpose)?;
                if !originals.is_some_and(|pass| pass.covers(self)) {
                    require_semantic_original_in_scope(reader, self.semantic)?;
                }
                self.require_metadata_in_scope(reader)?;
                Ok(names)
            });
        }
        let names =
            operation_inventory_in_tree(&self.operation, self.purpose, tree.as_deref_mut())?;
        require_semantic_original_in_tree(&self.operation, self.semantic, tree.as_deref_mut())?;
        self.require_metadata_in_tree(tree)?;
        Ok(names)
    }

    fn require_operation_exit(
        &self,
        mut tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
        originals: Option<&retained_graph::OriginalReadPass<'_, '_>>,
    ) -> Result<Vec<std::ffi::OsString>> {
        if reuse_operation_scope()
            && let Some(tree) = tree.as_deref_mut()
        {
            #[cfg(test)]
            operation_scope_tests::bracket();
            return tree.read_scope(&self.operation, |reader| {
                self.require_metadata_in_scope(reader)?;
                if !originals.is_some_and(|pass| pass.covers(self)) {
                    require_semantic_original_in_scope(reader, self.semantic)?;
                }
                operation_inventory_in_scope(reader, self.purpose)
            });
        }
        self.require_metadata_in_tree(tree.as_deref_mut())?;
        require_semantic_original_in_tree(&self.operation, self.semantic, tree.as_deref_mut())?;
        operation_inventory_in_tree(&self.operation, self.purpose, tree)
    }

    fn require_metadata_in_scope(&self, reader: &mut iroha_fs::PrivateReadScope<'_>) -> Result<()> {
        let result = (|| {
            if read_record_in_scope::<Dispatch>(reader, "dispatch.nrt")? != self.dispatch
                || read_record_in_scope::<ClosurePlan>(reader, "closing.nrt")? != self.closing
                || read_record_in_scope::<ClosureRecord>(reader, "closed.nrt")? != self.closed
            {
                return Err(invalid(
                    "dispatch inventory changed during native operation",
                ));
            }
            Ok(())
        })();
        #[cfg(test)]
        operation_scope_tests::after_leaf(operation_scope_tests::Point::Metadata)?;
        result
    }

    fn require_metadata_in_tree(
        &self,
        tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
    ) -> Result<()> {
        #[cfg(test)]
        operation_scope_tests::bracket();
        match tree {
            Some(tree) => tree.read_scope(&self.operation, |reader| {
                self.require_metadata_in_scope(reader)
            }),
            None => self
                .operation
                .read_scope(|reader| self.require_metadata_in_scope(reader)),
        }
    }

    #[cfg(test)]
    pub(in crate::managed) fn test_operation_records<T>(
        read: impl FnOnce() -> T,
    ) -> (T, [usize; 4]) {
        tests::operation_record_work(read)
    }

    #[cfg(test)]
    pub(in crate::managed) fn test_current_local_in_tree(
        &self,
        tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
    ) -> Result<()> {
        self.require_current_local_in_tree(None, tree, None, None)
    }

    fn retain_root(&self, operation: &PrivateDirectory) -> Result<()> {
        self.require_current()?;
        self.scope.require_active()?;
        if operation.identity()? != self.operation.identity()?
            || self
                .dispatch
                .as_ref()
                .is_none_or(|value| value.state != ReservationState::Published)
        {
            return Err(invalid("dispatch root was not fully published"));
        }
        Ok(())
    }

    /// Compare every retained authorization before wallet inspection or native HTTP.
    pub(in crate::managed) fn require_fees(&self, fees: &super::Fees) -> Result<()> {
        fees.validate()?;
        self.scope.require_fees(fees)?;
        if self
            .dispatch
            .as_ref()
            .is_some_and(|value| &value.highest.terms.fees != fees)
            || self
                .attempts
                .iter()
                .any(|attempt| &attempt.terms().fees != fees)
        {
            return Err(invalid(
                "retained dispatch differs from the full original fee authorization",
            ));
        }
        Ok(())
    }

    pub(in crate::managed) fn selected(&self) -> Result<Option<&Attempt>> {
        self.scope.require_active()?;
        if self.closing.is_some()
            || self.closed.is_some()
            || self.reservation_pending()
            || self.empty_tail
        {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        let Some(last) = self.attempts.last() else {
            return Ok(None);
        };
        last.require_selected()?;
        Ok(Some(last))
    }
    /// Local epoch references only; callers must join them to the actual closed issuer custody.
    pub(in crate::managed) fn origins(&self) -> impl Iterator<Item = &Origin> {
        self.attempts.iter().map(Attempt::origin).chain(
            self.dispatch
                .iter()
                .filter(|value| usize::from(value.highest.ordinal) > self.attempts.len())
                .map(|value| &value.highest.origin),
        )
    }
    pub(in crate::managed) fn last(&self) -> Option<&Attempt> {
        self.attempts.last()
    }
    pub(in crate::managed) fn predecessor(&self) -> Option<&Attempt> {
        self.attempts
            .len()
            .checked_sub(2)
            .and_then(|index| self.attempts.get(index))
    }

    /// Original terms remain available even before the exact anchored child is published.
    pub(in crate::managed) fn retained_terms(&self) -> Option<&Terms> {
        self.dispatch.as_ref().map(|value| &value.highest.terms)
    }

    pub(in crate::managed) fn reserved_attempt_count(&self) -> usize {
        self.dispatch
            .as_ref()
            .map_or(0, |value| usize::from(value.highest.ordinal))
    }
    pub(in crate::managed) fn cumulative_reserved_count(&self) -> usize {
        // History::read checked the sum once against the sole shared finite bound.
        self.cumulative_reserved
    }
    fn reservation_pending(&self) -> bool {
        self.dispatch
            .as_ref()
            .is_some_and(|value| value.state == ReservationState::Reserved)
    }
    fn finish_reserved(
        &self,
        operation: &PrivateDirectory,
        closing: bool,
    ) -> Result<Option<Attempt>> {
        self.require_current()?;
        if !closing {
            self.scope.require_active()?;
        }
        if operation.identity()? != self.operation.identity()? {
            return Err(invalid("dispatch selected another operation custody"));
        }
        let Some(old) = self
            .dispatch
            .as_ref()
            .filter(|value| value.state == ReservationState::Reserved)
        else {
            return Ok(None);
        };
        let root = match &self.root {
            Some(root) => root.retain()?,
            None => operation.create_child("attempts")?,
        };
        let name = format!("{:04}", old.highest.ordinal);
        let directory = match root.open_child_optional(&name)? {
            Some(value) => value,
            None => root.create_child(&name)?,
        };
        let names = measured_inventory!(AttemptInventory, directory.entries(1))?;
        if names.iter().any(|name| name != "authorization.nrt") {
            return Err(invalid("reserved attempt contains unexpected material"));
        }
        write_record(&directory, "authorization.nrt", &old.highest)?;
        let mut published = old.clone();
        published.state = ReservationState::Published;
        replace_dispatch(operation, Some(old), &published)?;
        Ok(Some(Attempt {
            directory,
            authorization: old.highest.clone(),
            observation: None,
            commit: None,
            retirement: None,
        }))
    }
    /// Reserve exact original terms before publishing their child, without any wallet effect.
    pub(in crate::managed) fn reserve(
        &self,
        operation: &PrivateDirectory,
        origin: Origin,
        terms: Terms,
    ) -> Result<Attempt> {
        self.reserve_pending(operation, origin, terms)?;
        Self::read_retained(operation, self.purpose, self.semantic, &self.scope, self)?
            .finish_reserved(operation, false)?
            .ok_or_else(|| invalid("new dispatch reservation was not retained"))
    }
    fn reserve_pending(
        &self,
        operation: &PrivateDirectory,
        origin: Origin,
        terms: Terms,
    ) -> Result<()> {
        self.require_current()?;
        self.scope.require_active()?;
        if self.closing.is_some() || self.closed.is_some() || self.reservation_pending() {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        terms.validate()?;
        self.scope.require_fees(&terms.fees)?;
        validate_origin(&origin)?;
        let index = self
            .reserved_attempt_count()
            .checked_add(1)
            .ok_or_else(|| invalid("dispatch count overflow"))?;
        if self
            .scope
            .prior_total()
            .checked_add(index)
            .is_none_or(|total| total > MAX_ATTEMPTS)
        {
            return Err(ManagedBootstrapFailure::EpochLimit.into());
        }
        let authorization = Authorization {
            ordinal: u8::try_from(index).map_err(|_| invalid("dispatch ordinal overflow"))?,
            purpose: self.purpose,
            semantic: self.semantic,
            previous: self.attempts.last().map(Attempt::digest).transpose()?,
            origin,
            terms,
        };
        if let Some(prior) = self.attempts.last() {
            validate_successor(&prior.authorization, &authorization)?;
        }
        if operation.identity()? != self.operation.identity()? {
            return Err(invalid("dispatch selected another operation custody"));
        }
        let reserved = Dispatch {
            purpose: self.purpose,
            semantic: self.semantic,
            first: self
                .dispatch
                .as_ref()
                .map(|value| value.first)
                .unwrap_or(digest(&authorization)?),
            scope: self.scope.commitment()?,
            highest: authorization,
            state: ReservationState::Reserved,
        };
        replace_dispatch(operation, self.dispatch.as_ref(), &reserved)
    }
}

fn operation_inventory(
    operation: &PrivateDirectory,
    purpose: Purpose,
) -> Result<Vec<std::ffi::OsString>> {
    checked_operation_inventory(
        measured_inventory!(AttemptInventory, operation.entries(6))?,
        purpose,
    )
}

fn checked_operation_inventory(
    names: Vec<std::ffi::OsString>,
    purpose: Purpose,
) -> Result<Vec<std::ffi::OsString>> {
    let enrollment = scope::is_enrollment(purpose);
    if names.iter().any(|name| {
        name != "original.nrt"
            && name != "dispatch.nrt"
            && name != "attempts"
            && !(enrollment
                && ["reserved.nrt", "closing.nrt", "closed.nrt"]
                    .iter()
                    .any(|allowed| name == *allowed))
    }) {
        return Err(invalid("dispatch operation contains unknown material"));
    }
    Ok(names)
}

fn require_semantic_original(operation: &PrivateDirectory, semantic: [u8; 32]) -> Result<()> {
    #[cfg(test)]
    graph_original_tests::record_original_read();
    let intent = read_optional(
        operation,
        "original.nrt",
        super::MAX_CHECKPOINT_BYTES + 3 * 1024 * 1024,
    )?
    .ok_or_else(|| invalid("dispatch lost its original semantic intent"))?;
    if *Hash::new(&intent).as_ref() != semantic {
        return Err(invalid("dispatch semantic original was changed"));
    }
    Ok(())
}

// These read-only adapters retain the sole native leaf/census producers. The graph owner
// chooses the existing ancestry bracket; no pathname or validation result supplies coverage.
fn directory_entries_in_tree(
    directory: &PrivateDirectory,
    maximum: usize,
    tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
) -> Result<Vec<std::ffi::OsString>> {
    match tree {
        Some(tree) => tree.read_scope(directory, |reader| {
            Ok(measured_inventory!(
                AttemptScopedInventory,
                reader.entries(maximum)
            )?)
        }),
        None => Ok(measured_inventory!(
            AttemptInventory,
            directory.entries(maximum)
        )?),
    }
}

fn revalidate_directory_in_tree(
    directory: &PrivateDirectory,
    tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
) -> Result<()> {
    match tree {
        Some(tree) => tree.revalidate_directory(directory)?,
        None => directory.revalidate()?,
    }
    Ok(())
}

fn reuse_operation_scope() -> bool {
    #[cfg(test)]
    if operation_scope_tests::original_recipe() {
        return false;
    }
    !norito::core::decode_limits_active()
}

fn operation_inventory_in_scope(
    reader: &mut iroha_fs::PrivateReadScope<'_>,
    purpose: Purpose,
) -> Result<Vec<std::ffi::OsString>> {
    let result = measured_inventory!(AttemptScopedInventory, reader.entries(6))
        .map_err(crate::managed::Error::from)
        .and_then(|names| checked_operation_inventory(names, purpose));
    #[cfg(test)]
    operation_scope_tests::after_leaf(operation_scope_tests::Point::Inventory)?;
    result
}

fn operation_inventory_in_tree(
    operation: &PrivateDirectory,
    purpose: Purpose,
    tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
) -> Result<Vec<std::ffi::OsString>> {
    match tree {
        Some(tree) => {
            #[cfg(test)]
            operation_scope_tests::bracket();
            tree.read_scope(operation, |reader| {
                operation_inventory_in_scope(reader, purpose)
            })
        }
        None => operation_inventory(operation, purpose),
    }
}

fn require_semantic_original_in_scope(
    reader: &mut iroha_fs::PrivateReadScope<'_>,
    semantic: [u8; 32],
) -> Result<()> {
    #[cfg(test)]
    graph_original_tests::record_original_read();
    let result = (|| {
        let original = reader
            .read_optional(
                "original.nrt",
                super::MAX_CHECKPOINT_BYTES + 3 * 1024 * 1024,
                |bytes| *Hash::new(bytes).as_ref(),
            )?
            .ok_or_else(|| invalid("dispatch lost its original semantic intent"))?;
        if original != semantic {
            return Err(invalid("dispatch semantic original was changed"));
        }
        Ok(())
    })();
    #[cfg(test)]
    operation_scope_tests::after_leaf(operation_scope_tests::Point::Semantic)?;
    result
}

fn require_semantic_original_in_tree(
    operation: &PrivateDirectory,
    semantic: [u8; 32],
    tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
) -> Result<()> {
    let Some(tree) = tree else {
        return require_semantic_original(operation, semantic);
    };
    #[cfg(test)]
    operation_scope_tests::bracket();
    tree.read_scope(operation, |reader| {
        require_semantic_original_in_scope(reader, semantic)
    })
}

fn attempt_inventory(directory: &PrivateDirectory) -> Result<Vec<std::ffi::OsString>> {
    checked_attempt_inventory(measured_inventory!(AttemptInventory, directory.entries(7))?)
}

fn checked_attempt_inventory(names: Vec<std::ffi::OsString>) -> Result<Vec<std::ffi::OsString>> {
    if names.iter().any(|name| {
        ![
            "authorization.nrt",
            "observation.nrt",
            "committed.nrt",
            "retired.nrt",
            "transaction",
            "replay.nrt",
            "carrier.nrt",
        ]
        .iter()
        .any(|allowed| name == OsStr::new(allowed))
    }) {
        return Err(invalid("dispatch attempt contains unknown material"));
    }
    Ok(names)
}

fn replace_dispatch(
    operation: &PrivateDirectory,
    expected: Option<&Dispatch>,
    next: &Dispatch,
) -> Result<()> {
    operation.revalidate()?;
    let identity = operation.identity()?;
    if read_record::<Dispatch>(operation, "dispatch.nrt")?.as_ref() != expected {
        return Err(invalid("dispatch high-water changed before publication"));
    }
    let valid = match expected {
        None => {
            next.state == ReservationState::Reserved
                && next.highest.ordinal == 1
                && next.highest.previous.is_none()
                && next.first == digest(&next.highest)?
        }
        Some(old) => {
            let same = old.purpose == next.purpose
                && old.semantic == next.semantic
                && old.first == next.first
                && old.scope == next.scope;
            same && match (old.state, next.state) {
                (ReservationState::Reserved, ReservationState::Published) => {
                    old.highest == next.highest
                }
                (ReservationState::Published, ReservationState::Reserved) => {
                    usize::from(next.highest.ordinal) == usize::from(old.highest.ordinal) + 1
                        && next.highest.previous == Some(digest(&old.highest)?)
                }
                _ => false,
            }
        }
    };
    if !valid {
        return Err(invalid("illegal dispatch high-water transition"));
    }
    let bytes = encode(next, MAX_RECORD_BYTES)?;
    operation.write_atomic(
        "dispatch.nrt",
        &bytes,
        if expected.is_some() {
            PublishMode::Replace
        } else {
            PublishMode::CreateNew
        },
    )?;
    if operation.identity()? != identity
        || read_record::<Dispatch>(operation, "dispatch.nrt")?.as_ref() != Some(next)
    {
        return Err(invalid("dispatch high-water changed during publication"));
    }
    operation.revalidate()?;
    Ok(())
}

/// Retain exact no-wallet retirement under the purpose lock; no decoded marker supplies proof.
pub(in crate::managed) fn retire_missing(previous: &Attempt, successor: &Attempt) -> Result<()> {
    if previous.is_committed() {
        return Err(invalid(
            "a committed dispatch cannot infer unsigned absence from a missing wallet",
        ));
    }
    let names = measured_inventory!(AttemptInventory, previous.directory.entries(7))?;
    if names.iter().any(|name| {
        ![
            "authorization.nrt",
            "observation.nrt",
            "committed.nrt",
            "retired.nrt",
        ]
        .iter()
        .any(|allowed| name == OsStr::new(allowed))
    }) {
        return Err(invalid(
            "missing-wallet retirement refuses later or unknown material",
        ));
    }
    write_retirement(previous, successor, RetirementKind::Missing)
}

/// Consume only the canonical purpose owner's opaque exact RequestOnly retirement receipt.
pub(in crate::managed) fn retire_request(
    previous: &Attempt,
    successor: &Attempt,
    receipt: &RetiredNativeRequest,
) -> Result<()> {
    if receipt.journal_path() != previous.wallet_path() || !valid_sha256(receipt.request_sha256()) {
        return Err(invalid(
            "wallet retirement receipt selected another original request",
        ));
    }
    write_retirement(
        previous,
        successor,
        RetirementKind::Request {
            request_sha256: receipt.request_sha256().to_owned(),
        },
    )
}

fn write_retirement(previous: &Attempt, successor: &Attempt, kind: RetirementKind) -> Result<()> {
    previous.verify_authorization()?;
    successor.verify_authorization()?;
    if let (Some(commit), RetirementKind::Request { request_sha256 }) = (&previous.commit, &kind) {
        if commit.request_sha256 != *request_sha256 {
            return Err(invalid("retirement changed the committed wallet request"));
        }
    }
    if successor.authorization.previous != Some(previous.digest()?)
        || successor.authorization.purpose != previous.authorization.purpose
        || successor.authorization.semantic != previous.authorization.semantic
    {
        return Err(invalid(
            "unsigned retirement has another native intent or predecessor",
        ));
    }
    if read_optional(
        &previous.directory,
        "carrier.nrt",
        super::MAX_CHECKPOINT_BYTES,
    )?
    .is_some()
        || read_optional(
            &previous.directory,
            "replay.nrt",
            super::MAX_CHECKPOINT_BYTES,
        )?
        .is_some()
    {
        return Err(invalid("native carrier custody cannot be retired"));
    }
    write_record(
        &previous.directory,
        "retired.nrt",
        &Retirement {
            authorization: previous.digest()?,
            successor: successor.digest()?,
            kind,
        },
    )
}

/// The caller has just authenticated the concrete native prerequisite. Commit its exact selected
/// observation, canonical RequestOnly commitment and predecessor retirement before payload
/// preparation or signing can begin.
pub(in crate::managed) fn commit(
    attempt: &Attempt,
    previous: Option<&Attempt>,
    observation: Observation,
    preparation: &VerifiedNativePreparation,
) -> Result<()> {
    attempt.verify_authorization()?;
    if let Some(previous) = previous {
        previous.verify_authorization()?;
    }
    if preparation.phase() != NativePreparationPhase::RequestOnly {
        return Err(invalid(
            "dispatch commit requires the exact retained unsigned wallet request",
        ));
    }
    let request_sha256 = preparation
        .request_sha256()
        .ok_or_else(|| invalid("retained wallet request has no canonical commitment"))?;
    if !valid_sha256(request_sha256) {
        return Err(invalid("invalid original wallet request commitment"));
    }
    observation.validate(&attempt.authorization)?;
    let authorization_digest = attempt.digest()?;
    let retirement: Option<Retirement> = previous
        .map(|prior| {
            read_record(&prior.directory, "retired.nrt")
                .and_then(|value| value.ok_or_else(|| invalid("predecessor retirement absent")))
        })
        .transpose()?;
    if attempt.authorization.previous != previous.map(Attempt::digest).transpose()?
        || retirement
            .as_ref()
            .is_some_and(|value| value.successor != authorization_digest)
    {
        return Err(invalid("dispatch commit has another predecessor"));
    }
    if read_record::<Observation>(&attempt.directory, "observation.nrt")? != Some(observation) {
        return Err(invalid("dispatch commit lost its selected observation"));
    }
    write_record(
        &attempt.directory,
        "committed.nrt",
        &Commit {
            authorization: attempt.digest()?,
            observation: digest(&observation)?,
            request_sha256: request_sha256.to_owned(),
            previous_retirement: retirement.as_ref().map(digest).transpose()?,
        },
    )
}

pub(in crate::managed) fn semantic_digest<T: norito::NoritoSerialize>(
    value: &T,
    maximum: usize,
) -> Result<[u8; 32]> {
    Ok(*Hash::new(encode(value, maximum)?).as_ref())
}
fn digest<T: norito::NoritoSerialize>(value: &T) -> Result<[u8; 32]> {
    semantic_digest(value, MAX_RECORD_BYTES)
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn validate_origin(origin: &Origin) -> Result<()> {
    if let Origin::Generated {
        ordinal,
        epoch,
        parent_intent,
    } = origin
    {
        if *ordinal == 0
            || usize::from(*ordinal) > MAX_ATTEMPTS
            || *epoch == [0; 32]
            || *parent_intent == [0; 32]
        {
            return Err(invalid(
                "dispatch refers to an invalid generated authorization epoch",
            ));
        }
    }
    Ok(())
}

fn validate_successor(previous: &Authorization, successor: &Authorization) -> Result<()> {
    if previous.terms.fees != successor.terms.fees || matches!(successor.origin, Origin::Explicit) {
        return Err(invalid(
            "unsigned successor changed fixed fees or lacks a generated epoch",
        ));
    }
    if let (
        Origin::Generated {
            ordinal: before,
            parent_intent: original,
            ..
        },
        Origin::Generated {
            ordinal: after,
            parent_intent: current,
            ..
        },
    ) = (&previous.origin, &successor.origin)
    {
        if after <= before || original != current {
            return Err(invalid(
                "unsigned successor did not advance the same parent authorization history",
            ));
        }
    }
    Ok(())
}
pub(in crate::managed) fn read_record<
    T: norito::NoritoSerialize + for<'a> norito::NoritoDeserialize<'a>,
>(
    directory: &PrivateDirectory,
    name: &str,
) -> Result<Option<T>> {
    #[cfg(test)]
    let _read_timing = finish_timing::phase(finish_timing::Phase::AttemptRecordRead);
    #[cfg(test)]
    tests::parse_digest_tests::record_read();
    let Some(bytes) = read_optional(directory, name, MAX_RECORD_BYTES)? else {
        return Ok(None);
    };
    let value = {
        #[cfg(test)]
        let _decode_timing = finish_timing::phase(finish_timing::Phase::AttemptRecordDecode);
        decode_record(&bytes)
    }?;
    #[cfg(test)]
    tests::parse_digest_tests::record_decoded();
    Ok(Some(value))
}
// The same canonical decoder and physical test counters, under a caller-owned closed
// directory bracket. Missing leaves remain distinct from its unconditional custody exit.
fn read_record_in_scope<T: norito::NoritoSerialize + for<'a> norito::NoritoDeserialize<'a>>(
    reader: &mut iroha_fs::PrivateReadScope<'_>,
    name: &str,
) -> Result<Option<T>> {
    #[cfg(test)]
    let _read_timing = finish_timing::phase(finish_timing::Phase::AttemptScopedRecordRead);
    #[cfg(test)]
    tests::parse_digest_tests::record_read();
    #[cfg(test)]
    let decode = |bytes: &[u8]| {
        let _timing = finish_timing::phase(finish_timing::Phase::AttemptScopedRecordDecode);
        decode_record::<T>(bytes)
    };
    #[cfg(not(test))]
    let decode = decode_record::<T>;
    let Some(value) = reader.read_optional(name, MAX_RECORD_BYTES, decode)? else {
        return Ok(None);
    };
    let value = value?;
    #[cfg(test)]
    tests::parse_digest_tests::record_decoded();
    Ok(Some(value))
}
/// Decode one already bounded record image with the sole original dispatch codec limits.
pub(in crate::managed) fn decode_record<
    T: norito::NoritoSerialize + for<'a> norito::NoritoDeserialize<'a>,
>(
    bytes: &[u8],
) -> Result<T> {
    norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES * 8,
            32,
        ),
    )
    .map_err(|_| invalid("invalid canonical dispatch custody record"))
}
pub(in crate::managed) fn write_record<T: norito::NoritoSerialize>(
    directory: &PrivateDirectory,
    name: &str,
    value: &T,
) -> Result<()> {
    #[cfg(test)]
    let _closure_timing = finish_timing::phase_in_closure(finish_timing::Phase::ClosureRecordWrite);
    let bytes = encode(value, MAX_RECORD_BYTES)?;
    if let Some(retained) = read_optional(directory, name, MAX_RECORD_BYTES)? {
        if retained != bytes {
            return Err(invalid("immutable dispatch custody record changed"));
        }
        return Ok(());
    }
    directory.write_atomic(name, &bytes, PublishMode::CreateNew)?;
    Ok(())
}

#[cfg(test)]
#[path = "attempts/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "attempts/retained_handle_census_tests.rs"]
mod retained_handle_census_tests;

#[cfg(test)]
#[path = "attempts/measurement_tests.rs"]
mod measurement_tests;
