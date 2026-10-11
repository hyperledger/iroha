//! Pure invocation identities and single-owner canonical execution outputs.
//!
//! `BlockResult` owns these rows separately from immutable network inputs.
//! Shape checks cannot authenticate an event, action, execution, receipt, State
//! observation or finality. Core execution and exact global executed-wire finality
//! must establish those facts; a public model constructor grants no authority.
//!
//! TODO: the canonical producer must reserve bounded terminal-output capacity
//! before executing a callback. The adjacent output budget checks exact row
//! capacity, but Core must authenticate its plan and account for metadata and
//! allocation before work. Callers must enforce encoded and allocation limits
//! before decoding, then validate shape. A successful shape check is not acceptance.

use std::collections::BTreeSet;

use iroha_crypto::{Hash, HashOf};
use norito::codec::{Decode, Encode};

use super::BlockHeader;
use crate::{
    events::{time::TimeEvent, trigger_completed::TriggerCompletedOutcome},
    transaction::signed::{ExecutionStep, TransactionEntrypoint, TransactionResult},
    trigger::TriggerId,
};

const PIPELINE_CALL_DOMAIN: &[u8] = b"iroha:pipeline-invocation:v1\0";
const TIME_CALL_DOMAIN: &[u8] = b"iroha:time-invocation:v1\0";

/// Fixed canonical failure text used by a pre-reserved output-limit terminal.
///
/// The typed `LimitCheck` and exact bounded row shape, not arbitrary Display
/// text, distinguish this failure from a callback fault or a local allocator
/// failure. The latter must not enter canonical execution results.
pub const EXECUTION_OUTPUT_LIMIT_REASON: &str = "execution output exceeds consensus byte limit";

/// Bounded diagnostic for an actual rejected Network execution whose full error
/// does not fit. Its economic disposition is decided from the original typed
/// rejection before this projection; this never denotes healthy-work rollback.
pub const NETWORK_REJECTION_DIAGNOSTIC_OMITTED: &str = "execution rejected; diagnostic omitted";

/// Bounded projection of a real internal rejection whose diagnostic did not fit.
/// Core decides rollback, quarantine or retry disposition from the original
/// typed error before projection; this never denotes healthy output overflow.
pub const INTERNAL_REJECTION_DIAGNOSTIC_OMITTED: &str = "callback failed; diagnostic omitted";

/// Position of a deterministic pipeline event in its applying carrier.
///
/// Network positions are source indices, not a compressed list of matched
/// events. `BlockApproved` follows every network event. Advertised results are
/// never event inputs; Core must construct events from actual prefix execution.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::PipelineEventPositionV1")]
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PipelineEventPositionV1 {
    /// Actual signed-input event at the complete network-source position.
    Network(u32),
    /// Approved-block event derived from the proposal-only header.
    BlockApproved,
}

/// Untrusted description of the persistent trigger action used by an invocation.
///
/// The digest is not proof of an action or a globally unique incarnation. Core
/// must reload and canonically bind the actual action under exact applying State.
/// Transaction-local lifecycle generations and prepared caches are not inputs.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::TriggerUseV1")]
#[norito(deny_unknown_fields)]
pub struct TriggerUseV1 {
    /// Trigger whose use-time action was selected.
    pub trigger_id: TriggerId,
    /// Persistent registration height; zero is valid for genesis fixtures/state.
    pub registered_at_height: u64,
    /// Canonical persistent use-time action digest, including its actual authority.
    ///
    /// The execution owner authenticates the action in State; no duplicate authority
    /// claim or loaded-cache representation is carried in this descriptor.
    pub action_hash: Hash,
}

/// One pipeline candidate that was actually invoked after use-time revalidation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::PipelineInvocationV1")]
#[norito(deny_unknown_fields)]
pub struct PipelineInvocationV1 {
    /// Deterministic source event position.
    pub event: PipelineEventPositionV1,
    /// Original matched-ID position; skipped candidates may leave gaps.
    pub candidate_index: u32,
    /// Actual use-time action claim, authenticated only by Core re-execution.
    pub trigger: TriggerUseV1,
}

impl PipelineInvocationV1 {
    /// Derive the pre-body call key from the immutable proposal and descriptor.
    ///
    /// No result, output index, receipt, fragment count or finality enters this
    /// preimage. A caller-supplied proposal hash does not grant authority.
    ///
    /// # Errors
    /// Rejects zero proposal/action identities and canonical encoding errors.
    pub fn execution_call_hash(&self, proposal: HashOf<BlockHeader>) -> Result<Hash, String> {
        validate_action(&self.trigger)?;
        invocation_hash(PIPELINE_CALL_DOMAIN, proposal, self)
    }
}

/// One actual matched scheduled-Time occurrence, independent of display steps.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::TimeInvocationV1")]
#[norito(deny_unknown_fields)]
pub struct TimeInvocationV1 {
    /// Original deterministic schedule position, including retry ordering.
    pub schedule_index: u32,
    /// Actual parent/current time interval, which Core must independently verify.
    pub event: TimeEvent,
    /// Actual use-time action claim, authenticated only by Core re-execution.
    pub trigger: TriggerUseV1,
}

impl TimeInvocationV1 {
    /// Derive a pre-body call key that distinguishes equal displayed programs.
    ///
    /// # Errors
    /// Rejects zero identities, overflowing interval arithmetic and encoding errors.
    pub fn execution_call_hash(&self, proposal: HashOf<BlockHeader>) -> Result<Hash, String> {
        validate_action(&self.trigger)?;
        self.event
            .interval
            .since_ms
            .checked_add(self.event.interval.length_ms)
            .ok_or_else(|| "Time invocation interval overflows u64".to_owned())?;
        invocation_hash(TIME_CALL_DOMAIN, proposal, self)
    }
}

/// Diagnostic root instructions retained only for a rolled-back invocation.
///
/// Program-bearing variants never claim application. The output-limit variant
/// explicitly omits program bytes. Successful trigger roots appear first in the
/// single full result sequence and never also occur in this diagnostic.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::TriggerFailureRootV1")]
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum TriggerFailureRootV1 {
    /// Root failed; this is only the existing declared instruction projection.
    DeclaredInstructionProjection(ExecutionStep),
    /// Root returned this step, but a later chained failure rolled it back.
    ReturnedBeforeRollback(ExecutionStep),
    /// The invocation was rolled back because its complete output did not fit.
    /// No unbounded program projection or partial successful trace is retained.
    /// Valid only in the exact bounded output-limit rejection row.
    OmittedByOutputLimit,
    /// A real invocation rejection was retained without its oversized diagnostic.
    /// Valid only with the exact bounded internal-rejection result and sole root
    /// failure completion. This is not a declaration of an executed root step.
    OmittedAfterRejection,
}

/// Completion owned by one output's execution call, not a synthetic entrypoint.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::InvocationCompletionV1")]
#[norito(deny_unknown_fields)]
pub struct InvocationCompletionV1 {
    /// Actual local invocation ordinal, allocated before execution; root is zero.
    pub callback_index: u32,
    /// Trigger that produced this completion.
    pub trigger_id: TriggerId,
    /// Retained callback outcome; shape does not authenticate this claim.
    pub outcome: TriggerCompletedOutcome,
}

/// One canonical top-level execution owner and its full result, stored once.
///
/// Successful internal results contain root first, then chained steps. Nested
/// by-call/data execution inherits this row's call key and never creates another
/// top-level result. Completion records are children of this sole row.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::ExecutionOutputV1")]
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ExecutionOutputV1 {
    /// Full result owned by one authenticated network input.
    Network(NetworkExecutionOutputV1),
    /// Full result owned by one pipeline invocation.
    Pipeline(PipelineExecutionOutputV1),
    /// Full result owned by one scheduled invocation.
    Time(TimeExecutionOutputV1),
}

/// Full execution result for one network source; the input body is not duplicated.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::NetworkExecutionOutputV1")]
#[norito(deny_unknown_fields)]
pub struct NetworkExecutionOutputV1 {
    /// Position in the complete ordinary or native network projection.
    pub input_index: u32,
    /// Full applied or rejected result, including independent per-leg receipts.
    pub result: TransactionResult,
    /// Applied completion records owned by this input's execution call.
    /// Empty on rejection because the whole input's callback state is rolled back.
    pub completions: Vec<InvocationCompletionV1>,
}

/// Full result of one independently applied or rolled-back pipeline invocation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::PipelineExecutionOutputV1")]
#[norito(deny_unknown_fields)]
pub struct PipelineExecutionOutputV1 {
    /// Pre-body event/action occurrence claim.
    pub invocation: PipelineInvocationV1,
    /// Full result, including root-first successful trace and receipts.
    pub result: TransactionResult,
    /// Explicitly absent on success; diagnostic only after rollback.
    #[norito(required)]
    pub failure_root: Option<TriggerFailureRootV1>,
    /// Completion records owned by this exact root call.
    /// Rejection retains only callback zero's failure for the whole invocation.
    pub completions: Vec<InvocationCompletionV1>,
}

/// Full result of one scheduled occurrence, without a synthetic network input.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::block::execution_output::TimeExecutionOutputV1")]
#[norito(deny_unknown_fields)]
pub struct TimeExecutionOutputV1 {
    /// Pre-body schedule/action occurrence claim.
    pub invocation: TimeInvocationV1,
    /// Full result, including root-first successful trace and receipts.
    pub result: TransactionResult,
    /// Explicitly absent on success; diagnostic only after rollback.
    #[norito(required)]
    pub failure_root: Option<TriggerFailureRootV1>,
    /// Completion records owned by this exact root call.
    /// Rejection retains only callback zero's failure for the whole invocation.
    pub completions: Vec<InvocationCompletionV1>,
}

/// Borrowed random access to the complete network-input projection.
///
/// Implementations must expose the same immutable ordering throughout a check.
/// This view grants no authentication authority. It avoids flattening native
/// groups by cloning their transaction bodies, or scanning from the start for
/// every output. Core must separately authenticate the source and its custody.
pub trait ExecutionInputs {
    /// Exact count of network sources in the current projection.
    fn input_count(&self) -> usize;
    /// Borrow a source by zero-based canonical index.
    fn input_at(&self, index: usize) -> Option<&TransactionEntrypoint>;
}

impl ExecutionInputs for [TransactionEntrypoint] {
    fn input_count(&self) -> usize {
        self.len()
    }
    fn input_at(&self, index: usize) -> Option<&TransactionEntrypoint> {
        self.get(index)
    }
}

impl<const N: usize> ExecutionInputs for [TransactionEntrypoint; N] {
    fn input_count(&self) -> usize {
        N
    }
    fn input_at(&self, index: usize) -> Option<&TransactionEntrypoint> {
        self.get(index)
    }
}

impl ExecutionInputs for Vec<TransactionEntrypoint> {
    fn input_count(&self) -> usize {
        self.len()
    }
    fn input_at(&self, index: usize) -> Option<&TransactionEntrypoint> {
        self.get(index)
    }
}

impl ExecutionInputs for super::SignedBlock {
    fn input_count(&self) -> usize {
        self.network_entrypoint_count()
    }
    fn input_at(&self, index: usize) -> Option<&TransactionEntrypoint> {
        self.network_entrypoint_at(index)
    }
}

impl ExecutionOutputV1 {
    /// Construct the bounded terminal reserved for one immutable network source.
    ///
    /// This is a proposed fallback, not evidence that execution has occurred.
    pub fn network_output_limit_rejection(input_index: u32) -> Self {
        Self::Network(NetworkExecutionOutputV1 {
            input_index,
            result: output_limit_result(),
            completions: Vec::new(),
        })
    }

    /// Construct the bounded terminal before invoking a pipeline callback.
    ///
    /// The caller must authenticate this descriptor and roll back the complete
    /// invocation before publishing the fallback. This does not quarantine it.
    pub fn pipeline_output_limit_rejection(invocation: PipelineInvocationV1) -> Self {
        let completion = output_limit_completion(&invocation.trigger);
        Self::Pipeline(PipelineExecutionOutputV1 {
            invocation,
            result: output_limit_result(),
            failure_root: Some(TriggerFailureRootV1::OmittedByOutputLimit),
            completions: vec![completion],
        })
    }

    /// Construct the bounded terminal before invoking one scheduled occurrence.
    ///
    /// The caller must authenticate the actual schedule/action and roll back the
    /// complete invocation before publishing this capacity failure.
    pub fn time_output_limit_rejection(invocation: TimeInvocationV1) -> Self {
        let completion = output_limit_completion(&invocation.trigger);
        Self::Time(TimeExecutionOutputV1 {
            invocation,
            result: output_limit_result(),
            failure_root: Some(TriggerFailureRootV1::OmittedByOutputLimit),
            completions: vec![completion],
        })
    }

    /// Check the exact bounded terminal shape without authenticating its origin.
    ///
    /// This checks the typed reason, receipt absence, omitted internal diagnostic
    /// and sole root completion. It does not classify arbitrary error strings.
    pub fn is_output_limit_rejection(&self) -> bool {
        use crate::transaction::error::TransactionRejectionReason;

        if !matches!(
            &self.result().0,
            Err(TransactionRejectionReason::LimitCheck(error))
                if error.reason == EXECUTION_OUTPUT_LIMIT_REASON
        ) || !self.result().batch_transfer_outcomes().is_empty()
            || self.result().nexus_fee_receipt().is_some()
            || !self.result().contract_events().is_empty()
        {
            return false;
        }
        let (trigger, diagnostic, completions) = match self {
            Self::Network(output) => return output.completions.is_empty(),
            Self::Pipeline(output) => (
                &output.invocation.trigger,
                &output.failure_root,
                &output.completions,
            ),
            Self::Time(output) => (
                &output.invocation.trigger,
                &output.failure_root,
                &output.completions,
            ),
        };
        matches!(diagnostic, Some(TriggerFailureRootV1::OmittedByOutputLimit))
            && matches!(completions.as_slice(), [completion]
                if completion.callback_index == 0
                    && completion.trigger_id == trigger.trigger_id
                    && matches!(&completion.outcome, TriggerCompletedOutcome::Failure(reason)
                        if reason == EXECUTION_OUTPUT_LIMIT_REASON))
    }

    /// Recognize the exact bounded real-internal-rejection diagnostic shape.
    ///
    /// This does not authenticate execution or authorize quarantine/retry effects.
    /// The distinct omitted-root tag prevents confusion with healthy overflow.
    pub fn is_internal_rejection_diagnostic_omitted(&self) -> bool {
        use crate::transaction::error::TransactionRejectionReason;

        let (trigger, diagnostic, completions) = match self {
            Self::Network(_) => return false,
            Self::Pipeline(output) => (
                &output.invocation.trigger,
                &output.failure_root,
                &output.completions,
            ),
            Self::Time(output) => (
                &output.invocation.trigger,
                &output.failure_root,
                &output.completions,
            ),
        };
        matches!(&self.result().0,
            Err(TransactionRejectionReason::LimitCheck(error))
                if error.reason == INTERNAL_REJECTION_DIAGNOSTIC_OMITTED)
            && self.result().batch_transfer_outcomes().is_empty()
            && self.result().nexus_fee_receipt().is_none()
            && self.result().contract_events().is_empty()
            && matches!(
                diagnostic,
                Some(TriggerFailureRootV1::OmittedAfterRejection)
            )
            && matches!(completions.as_slice(), [completion]
                if completion.callback_index == 0
                    && completion.trigger_id == trigger.trigger_id
                    && matches!(&completion.outcome, TriggerCompletedOutcome::Failure(reason)
                        if reason == INTERNAL_REJECTION_DIAGNOSTIC_OMITTED))
    }

    /// Borrow the one full result without projecting away its receipts.
    pub fn result(&self) -> &TransactionResult {
        match self {
            Self::Network(NetworkExecutionOutputV1 { result, .. })
            | Self::Pipeline(PipelineExecutionOutputV1 { result, .. })
            | Self::Time(TimeExecutionOutputV1 { result, .. }) => result,
        }
    }

    /// Borrow this output's sole ordered completion collection.
    pub fn completions(&self) -> &[InvocationCompletionV1] {
        match self {
            Self::Network(NetworkExecutionOutputV1 { completions, .. })
            | Self::Pipeline(PipelineExecutionOutputV1 { completions, .. })
            | Self::Time(TimeExecutionOutputV1 { completions, .. }) => completions,
        }
    }

    /// Resolve the actual call owner from source index or pre-body invocation.
    ///
    /// Network `SealedReveal` uses the inner signed call identity; it retains its
    /// distinct outer source identity through `input_index`. No output enters the hash.
    ///
    /// # Errors
    /// Rejects absent network inputs and invalid invocation preimages.
    pub fn execution_call_hash<S: ExecutionInputs + ?Sized>(
        &self,
        proposal: HashOf<BlockHeader>,
        network_inputs: &S,
    ) -> Result<Hash, String> {
        match self {
            Self::Network(NetworkExecutionOutputV1 { input_index, .. }) => Ok(Hash::from(
                network_input(network_inputs, *input_index)?.execution_call_hash(),
            )),
            Self::Pipeline(PipelineExecutionOutputV1 { invocation, .. }) => {
                invocation.execution_call_hash(proposal)
            }
            Self::Time(TimeExecutionOutputV1 { invocation, .. }) => {
                invocation.execution_call_hash(proposal)
            }
        }
    }

    /// Validate one row's local structure without authenticating execution.
    ///
    /// This checks source positions, registration chronology, trace/diagnostic
    /// shape and completion order. It cannot establish callback completeness,
    /// actual receipts, action policy, resource feasibility or finality.
    ///
    /// # Errors
    /// Rejects malformed source, root, rollback receipt, or completion claims.
    pub fn validate_structure<S: ExecutionInputs + ?Sized>(
        &self,
        proposal_height: u64,
        network_inputs: &S,
    ) -> Result<(), String> {
        if proposal_height == 0 {
            return Err("execution output proposal height is zero".into());
        }
        let internal = match self {
            Self::Network(NetworkExecutionOutputV1 {
                input_index,
                result,
                completions,
            }) => {
                let input = network_input(network_inputs, *input_index)?;
                if let Some(receipt) = result.nexus_fee_receipt() {
                    receipt.validate_for_network_input(input, proposal_height)?;
                }
                if result.is_err() && !completions.is_empty() {
                    return Err("rolled-back Network output retains callback completions".into());
                }
                None
            }
            Self::Pipeline(PipelineExecutionOutputV1 {
                invocation,
                failure_root,
                ..
            }) => {
                if let PipelineEventPositionV1::Network(input_index) = invocation.event
                    && !matches!(
                        network_input(network_inputs, input_index)?,
                        TransactionEntrypoint::External(_) | TransactionEntrypoint::SealedReveal(_)
                    )
                {
                    return Err("pipeline event source has no signed transaction event".into());
                }
                Some((&invocation.trigger, failure_root))
            }
            Self::Time(TimeExecutionOutputV1 {
                invocation,
                failure_root,
                ..
            }) => {
                invocation
                    .event
                    .interval
                    .since_ms
                    .checked_add(invocation.event.interval.length_ms)
                    .ok_or_else(|| "Time invocation interval overflows u64".to_owned())?;
                Some((&invocation.trigger, failure_root))
            }
        };
        let result = self.result();
        if result.0.is_err() && !result.contract_events().is_empty() {
            return Err("rejected execution output cannot publish contract emissions".into());
        }
        for event in result.contract_events() {
            if !event.definition.validate() {
                return Err("contract emission has an invalid source definition".into());
            }
            let schema = norito::encode_canonical(&event.definition.payload_type)
                .map_err(|error| error.to_string())?;
            if event.payload.schema_hash
                != crate::smart_contract::entrypoint::entrypoint_return_schema_hash_v1(&schema)
                || event
                    .definition
                    .payload_type
                    .word_kinds_for_atoms(&event.payload.atoms)
                    .is_none()
            {
                return Err("contract emission payload does not match its exact schema".into());
            }
        }
        if result.0.is_err() && !result.batch_transfer_outcomes().is_empty() {
            return Err("rolled-back output retains batch-transfer receipts".into());
        }
        if let Some((trigger, failure_root)) = internal {
            if result.nexus_fee_receipt().is_some() {
                return Err("internal output cannot publish a Network Nexus receipt".into());
            }
            validate_action(trigger)?;
            if trigger.registered_at_height >= proposal_height {
                return Err("internal action was not registered before applying height".into());
            }
            match (&result.0, failure_root) {
                (Ok(steps), None)
                    if steps
                        .first()
                        .is_some_and(|step| step.id == trigger.trigger_id) => {}
                (Err(_), Some(_)) => {}
                _ => {
                    return Err("internal result root or failure diagnostic is inconsistent".into());
                }
            }
            if result.is_err()
                && !matches!(self.completions(), [completion]
                    if completion.callback_index == 0
                        && completion.trigger_id == trigger.trigger_id
                        && matches!(completion.outcome, TriggerCompletedOutcome::Failure(_)))
            {
                return Err("rolled-back internal output must retain only its root failure".into());
            }
            if matches!(
                failure_root,
                Some(TriggerFailureRootV1::OmittedByOutputLimit)
            ) && !self.is_output_limit_rejection()
            {
                return Err("omitted root is not an exact bounded output-limit terminal".into());
            }
            if matches!(
                failure_root,
                Some(TriggerFailureRootV1::OmittedAfterRejection)
            ) && !self.is_internal_rejection_diagnostic_omitted()
            {
                return Err("omitted root is not an exact bounded internal rejection".into());
            }
            if self.completions().first().is_some_and(|completion| {
                completion.callback_index == 0 && completion.trigger_id != trigger.trigger_id
            }) {
                return Err("root completion names a different trigger".into());
            }
        }
        if self
            .completions()
            .windows(2)
            .any(|pair| pair[0].callback_index >= pair[1].callback_index)
        {
            return Err("completion callback positions are duplicated or unordered".into());
        }
        Ok(())
    }
}

/// Check canonical source/phase order and unique top-level call ownership.
///
/// Exactly one Network row precedes internal rows for each supplied network
/// input. Pipeline candidates and Time schedule positions may have gaps after
/// actual use-time skips. Internal events/actions remain untrusted claims.
/// This is an allocated-value shape check, not an ingress/resource policy.
///
/// # Errors
/// Rejects missing/duplicate/foreign source rows, phase/order violations,
/// inconsistent Time intervals, duplicate calls and malformed local row shape.
pub fn validate_execution_outputs_v1<S: ExecutionInputs + ?Sized>(
    outputs: &[ExecutionOutputV1],
    proposal: HashOf<BlockHeader>,
    proposal_height: u64,
    network_inputs: &S,
) -> Result<(), String> {
    if proposal_height == 0 || Hash::from(proposal) == Hash::prehashed([0; Hash::LENGTH]) {
        return Err("execution output proposal identity or height is zero".into());
    }
    if u32::try_from(outputs.len()).is_err() || u32::try_from(network_inputs.input_count()).is_err()
    {
        return Err("execution output position exceeds u32".into());
    }
    let mut network_count = 0_usize;
    let mut phase = 0_u8;
    let mut previous_pipeline = None;
    let mut previous_time = None;
    let mut time_event = None;
    let mut pipeline_triggers = BTreeSet::new();
    let mut calls = BTreeSet::new();
    for output in outputs {
        output.validate_structure(proposal_height, network_inputs)?;
        match output {
            ExecutionOutputV1::Network(NetworkExecutionOutputV1 { input_index, .. }) => {
                if phase != 0 || usize::try_from(*input_index).ok() != Some(network_count) {
                    return Err("network outputs are missing, duplicated or unordered".into());
                }
                network_count += 1;
            }
            ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 { invocation, .. }) => {
                if phase == 2 {
                    return Err("pipeline output follows Time phase".into());
                }
                phase = 1;
                let position = (invocation.event, invocation.candidate_index);
                if previous_pipeline.is_some_and(|previous| previous >= position)
                    || !pipeline_triggers
                        .insert((invocation.event, invocation.trigger.trigger_id.clone()))
                {
                    return Err("pipeline candidate is duplicated or unordered".into());
                }
                previous_pipeline = Some(position);
            }
            ExecutionOutputV1::Time(TimeExecutionOutputV1 { invocation, .. }) => {
                phase = 2;
                if previous_time.is_some_and(|previous| previous >= invocation.schedule_index)
                    || time_event.is_some_and(|previous| previous != invocation.event)
                {
                    return Err("Time positions or interval are inconsistent".into());
                }
                previous_time = Some(invocation.schedule_index);
                time_event = Some(invocation.event);
            }
        }
        if !calls.insert(output.execution_call_hash(proposal, network_inputs)?) {
            return Err("multiple outputs claim one execution call".into());
        }
    }
    if network_count != network_inputs.input_count() {
        return Err("execution outputs omit a network source".into());
    }
    Ok(())
}

fn validate_action(trigger: &TriggerUseV1) -> Result<(), String> {
    if trigger.action_hash == Hash::prehashed([0; Hash::LENGTH]) {
        return Err("trigger use-time action digest is zero".into());
    }
    Ok(())
}

fn network_input<S: ExecutionInputs + ?Sized>(
    inputs: &S,
    index: u32,
) -> Result<&TransactionEntrypoint, String> {
    let entry = usize::try_from(index)
        .ok()
        .and_then(|index| inputs.input_at(index))
        .ok_or_else(|| "execution output network source is absent".to_owned())?;
    Ok(entry)
}

fn output_limit_result() -> TransactionResult {
    use crate::transaction::error::{TransactionLimitError, TransactionRejectionReason};

    TransactionResult::new(Err(TransactionRejectionReason::LimitCheck(
        TransactionLimitError {
            reason: EXECUTION_OUTPUT_LIMIT_REASON.to_owned(),
        },
    )))
}

fn output_limit_completion(trigger: &TriggerUseV1) -> InvocationCompletionV1 {
    InvocationCompletionV1 {
        callback_index: 0,
        trigger_id: trigger.trigger_id.clone(),
        outcome: TriggerCompletedOutcome::Failure(EXECUTION_OUTPUT_LIMIT_REASON.to_owned()),
    }
}

fn invocation_hash<T: norito::NoritoSerialize>(
    domain: &[u8],
    proposal: HashOf<BlockHeader>,
    descriptor: &T,
) -> Result<Hash, String> {
    if Hash::from(proposal) == Hash::prehashed([0; Hash::LENGTH]) {
        return Err("invocation proposal identity is zero".into());
    }
    let bytes = norito::encode_canonical(descriptor).map_err(|error| error.to_string())?;
    Ok(Hash::new_from_chunks(&[domain, proposal.as_ref(), &bytes]))
}

#[cfg(test)]
#[path = "execution_output_tests.rs"]
mod tests;
