//! Bounded indexed native history joined to the challenged Check in one certified walk.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::{
    query::{
        signer_check::{
            BorrowedCheckExecutionCutV1, NativeCustodyCheckPurposeV1, PreparedCheckExecutionV1,
            SignerCertifiedWalkV1, native_signed_entry_frame_v1,
        },
        stream_token_gateway::{
            commitment::instruction_digest,
            rows::{AcknowledgementRowV1, AdmissionRowV1, LeaseTerminalV1},
            storage::{GatewayCurrentV1, GatewayPolicyRecordV1},
        },
    },
    state::TransactionsReadOnly,
    sumeragi::certified_chain::{CertifiedBlock, QcVerification},
};
use iroha_crypto::Hash;
use iroha_data_model::{
    sorafs::stream_token_gateway::{
        STREAM_TOKEN_GATEWAY_RECONCILE_MAX_ITEMS_V1,
        native::StreamTokenGatewayExecutionV1 as Execution,
    },
    transaction::{Executable, ExecutableBatchItem},
};

// Bound target allocation independently of how many blocks the already-certified authority
// prefix needs. The original monotonic deadline is checked between every yielded block.
const MAX_TARGETS: usize = 8 * (STREAM_TOKEN_GATEWAY_RECONCILE_MAX_ITEMS_V1 as usize + 2) + 1;
const MAX_TARGET_BYTES: usize = 64 * 1024 * 1024;
const MAX_FINALITY_BYTES: usize = 64 * 1024 * 1024;

// Different predicates at the same height remain different targets. Only the same exact
// policy revision or admission sequence is shared by its multiple consumers.
enum ExpectedAction {
    RecorderPolicy(iroha_data_model::sorafs::reputation::ReputationJournalAuthorityPolicyRecordV1),
    ReputationAppend(crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::Source),
    ReputationCancellation {
        original: Record,
        recorder_policy_digest: [u8; 32],
        reason: iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationCancellationReasonV1,
    },
    Configure(GatewayPolicyRecordV1),
    Admit(AdmissionRowV1),
    Acknowledge(AcknowledgementRowV1),
    Terminal {
        original: Record,
        terminal: LeaseTerminalV1,
    },
}
struct Target {
    execution: Execution,
    policy_revision: u64,
    action: ExpectedAction,
}
struct Targets {
    recorder_policies: BTreeMap<
        [u8; 32],
        iroha_data_model::sorafs::reputation::ReputationJournalAuthorityPolicyRecordV1,
    >,
    policies: BTreeMap<u64, GatewayPolicyRecordV1>,
    admissions: BTreeSet<u64>,
    delivery_sources: BTreeSet<u64>,
    acknowledgements: BTreeSet<u64>,
    targets: Vec<Target>,
    bytes: usize,
}
impl Targets {
    fn new() -> Self {
        Self {
            recorder_policies: BTreeMap::new(),
            policies: BTreeMap::new(),
            admissions: BTreeSet::new(),
            delivery_sources: BTreeSet::new(),
            acknowledgements: BTreeSet::new(),
            targets: Vec::new(),
            bytes: 0,
        }
    }
    fn charge<T: norito::core::NoritoSerialize>(&mut self, value: &T) -> Result<(), Error> {
        self.bytes = self
            .bytes
            .checked_add(norito::canonical_frame_len(value).map_err(|_| Error::Execution)?)
            .filter(|size| *size <= MAX_TARGET_BYTES)
            .ok_or(Error::Execution)?;
        if self.targets.len() >= MAX_TARGETS {
            return Err(Error::Execution);
        }
        Ok(())
    }
    fn policy(
        &mut self,
        view: &StateView<'_>,
        prepared: &PreparedStreamTokenGatewayCheckV1,
        revision: u64,
    ) -> Result<(), Error> {
        if self.policies.contains_key(&revision) {
            return Ok(());
        }
        let record = storage::read_policy_record(
            view.world(),
            &prepared.expected.network_id,
            prepared.expected.qualification.gateway_id,
            revision,
        )
        .map_err(|_| Error::Execution)?;
        self.charge(&record)?;
        self.targets.push(Target {
            execution: record.execution.clone(),
            policy_revision: revision,
            action: ExpectedAction::Configure(record.clone()),
        });
        self.policies.insert(revision, record);
        Ok(())
    }
    fn recorder_policy(
        &mut self,
        record: &iroha_data_model::sorafs::reputation::ReputationJournalAuthorityPolicyRecordV1,
    ) -> Result<(), Error> {
        if let Some(existing) = self.recorder_policies.get(&record.policy_digest) {
            return if existing == record {
                Ok(())
            } else {
                Err(Error::Execution)
            };
        }
        record.validate().map_err(|_| Error::Execution)?;
        self.charge(record)?;
        self.targets.push(Target {
            execution: record.origin.execution().clone(),
            policy_revision: 0,
            action: ExpectedAction::RecorderPolicy(record.clone()),
        });
        self.recorder_policies
            .insert(record.policy_digest, record.clone());
        Ok(())
    }
    fn admission(
        &mut self,
        view: &StateView<'_>,
        prepared: &PreparedStreamTokenGatewayCheckV1,
        current: &GatewayCurrentV1,
        sequence: u64,
        now_ms: u64,
    ) -> Result<AdmissionRowV1, Error> {
        let row =
            check::read_admission(view, current, sequence, now_ms).map_err(|_| Error::Execution)?;
        let (source, _) =
            crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::read(
                view.world(),
                &prepared.expected.network_id,
                &row.record,
            )
            .map_err(|_| Error::Execution)?;
        self.recorder_policy(&source.recorder_policy)?;
        let revision = row.record.admitted_under.revision;
        self.policy(view, prepared, revision)?;
        if self
            .policies
            .get(&revision)
            .ok_or(Error::Execution)?
            .policy
            .qualification
            != row.record.admitted_under
        {
            return Err(Error::Execution);
        }
        if self.admissions.insert(sequence) {
            self.charge(&row)?;
            self.targets.push(Target {
                execution: row.execution.clone(),
                policy_revision: revision,
                action: ExpectedAction::Admit(row.clone()),
            });
        }
        self.delivery(view, prepared, current, &row.record, now_ms)?;
        Ok(row)
    }
    fn delivery(
        &mut self,
        view: &StateView<'_>,
        prepared: &PreparedStreamTokenGatewayCheckV1,
        current: &GatewayCurrentV1,
        original: &Record,
        now_ms: u64,
    ) -> Result<(), Error> {
        use iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryDispositionV1 as Disposition;
        if !self
            .delivery_sources
            .insert(original.outcome.binding.gateway_sequence)
        {
            return Ok(());
        }
        let (source, delivery) =
            crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::read(
                view.world(),
                &prepared.expected.network_id,
                original,
            )
            .map_err(|_| Error::Execution)?;
        match &delivery.disposition {
            Disposition::Delivered { execution, .. } => {
                self.charge(&source)?;
                self.targets.push(Target {
                    execution: execution.clone(),
                    policy_revision: original.admitted_under.revision,
                    action: ExpectedAction::ReputationAppend(source),
                });
            }
            Disposition::GovernanceCancelled {
                recorder_policy_digest,
                gateway_qualification,
                reason,
                execution,
            } => {
                let recorder_policy = crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::read_policy(
                    view.world(), *recorder_policy_digest).map_err(|_| Error::Execution)?;
                self.recorder_policy(&recorder_policy)?;
                self.policy(view, prepared, gateway_qualification.revision)?;
                if self
                    .policies
                    .get(&gateway_qualification.revision)
                    .ok_or(Error::Execution)?
                    .policy
                    .qualification
                    != *gateway_qualification
                {
                    return Err(Error::Execution);
                }
                self.charge(&delivery)?;
                self.targets.push(Target {
                    execution: execution.clone(),
                    policy_revision: gateway_qualification.revision,
                    action: ExpectedAction::ReputationCancellation {
                        original: original.clone(),
                        recorder_policy_digest: *recorder_policy_digest,
                        reason: *reason,
                    },
                });
            }
            Disposition::Expired { execution } => {
                // Expiry is committed atomically by the exact acknowledgement. Even an
                // Admission readback must authenticate that signed terminal execution.
                let rows = WorldGatewayRows::new(
                    view.world(),
                    &prepared.expected.network_id,
                    prepared.expected.qualification.gateway_id,
                )
                .map_err(|_| Error::Execution)?;
                let Some(GatewayRow::Acknowledgement(row)) = rows
                    .read(&GatewayRowKey::Acknowledgement(
                        original.outcome.binding.gateway_sequence,
                    ))
                    .map_err(|_| Error::Execution)?
                else {
                    return Err(Error::Execution);
                };
                if row.record != *original
                    || row.reputation_delivery != delivery
                    || row.execution != *execution
                {
                    return Err(Error::Execution);
                }
                self.acknowledgement(
                    view,
                    prepared,
                    current,
                    original.outcome.binding.gateway_sequence,
                    now_ms,
                )?;
            }
            Disposition::Excluded if !original.outcome.status.counts_for_provider() => {}
            Disposition::Pending => {}
            _ => return Err(Error::Execution),
        }
        Ok(())
    }
    fn acknowledgement(
        &mut self,
        view: &StateView<'_>,
        prepared: &PreparedStreamTokenGatewayCheckV1,
        current: &GatewayCurrentV1,
        sequence: u64,
        now_ms: u64,
    ) -> Result<(), Error> {
        if !self.acknowledgements.insert(sequence) {
            return Ok(());
        }
        let original = self.admission(view, prepared, current, sequence, now_ms)?;
        let rows = WorldGatewayRows::new(
            view.world(),
            &prepared.expected.network_id,
            prepared.expected.qualification.gateway_id,
        )
        .map_err(|_| Error::Execution)?;
        let Some(GatewayRow::Acknowledgement(row)) = rows
            .read(&GatewayRowKey::Acknowledgement(sequence))
            .map_err(|_| Error::Execution)?
        else {
            return Err(Error::Execution);
        };
        if row.record != original.record {
            return Err(Error::Execution);
        }
        let (_, delivery) =
            crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::read(
                view.world(),
                &prepared.expected.network_id,
                &row.record,
            )
            .map_err(|_| Error::Execution)?;
        if delivery != row.reputation_delivery {
            return Err(Error::Execution);
        }
        self.policy(view, prepared, row.policy_revision)?;
        self.charge(&row)?;
        self.targets.push(Target {
            execution: row.execution.clone(),
            policy_revision: row.policy_revision,
            action: ExpectedAction::Acknowledge(row),
        });
        Ok(())
    }
}

fn prepare_targets(
    view: &StateView<'_>,
    prepared: &PreparedStreamTokenGatewayCheckV1,
) -> Result<Targets, crate::execution_attempt::ExecutionAttemptError<Error>> {
    let Action::Check(check_claim) = &prepared.instruction.request.action else {
        return Err(Error::Invalid.into());
    };
    let current = storage::read_current(
        view.world(),
        &prepared.expected.network_id,
        prepared.expected.qualification.gateway_id,
    )
    .map_err(|_| Error::Execution)?
    .ok_or(Error::Execution)?;
    if current.policy.policy.qualification != prepared.expected.qualification {
        return Err(Error::Authority.into());
    }
    let tip = u64::try_from(view.block_hashes().len()).map_err(|_| Error::Finality)?;
    let now_ms = crate::sumeragi::certified_chain::committed_block(view, tip)
        .map_err(|error| error.map_rejection(|_| Error::Finality))?
        .block_time_ms();
    let mut targets = Targets::new();
    targets.policy(view, prepared, current.policy.policy.qualification.revision)?;
    match &check_claim.subject {
        Subject::Qualification => {}
        Subject::Admission {
            request_digest,
            result,
        }
        | Subject::Serving {
            request_digest,
            result,
        } => {
            let original = targets.admission(
                view,
                prepared,
                &current,
                result.record.outcome.binding.gateway_sequence,
                now_ms,
            )?;
            if original.record != result.record
                || transition::request_digest(&original.request).map_err(|_| Error::Execution)?
                    != *request_digest
            {
                return Err(Error::Execution.into());
            }
            let original_request = match &prepared.expected.selector {
                Selector::Admission(request) | Selector::Serving(request) => request,
                _ => return Err(Error::Invalid.into()),
            };
            if original.request != *original_request {
                return Err(Error::Execution.into());
            }
            if matches!(
                result.delivery_state,
                Delivery::AcknowledgedExactReplay { .. }
            ) {
                targets.acknowledgement(
                    view,
                    prepared,
                    &current,
                    result.record.outcome.binding.gateway_sequence,
                    now_ms,
                )?;
            }
        }
        Subject::Pending {
            max_items,
            readback_digest,
        } => {
            let pending = check::read_pending(view, &current, *max_items, now_ms)
                .map_err(|_| Error::Execution)?;
            if stream_token_gateway_pending_readback_digest_v1(
                prepared.expected.qualification,
                *max_items,
                &pending,
            )
            .map_err(|_| Error::Execution)?
                != *readback_digest
            {
                return Err(Error::Execution.into());
            }
            for record in &pending.records {
                let original = targets.admission(
                    view,
                    prepared,
                    &current,
                    record.outcome.binding.gateway_sequence,
                    now_ms,
                )?;
                if original.record != *record {
                    return Err(Error::Execution.into());
                }
            }
            // Prefix endpoints remain authenticated even when the requested prefix is empty or
            // shorter than the remaining history. No historical mutation journal is scanned.
            if pending.acknowledged_through_sequence != 0 {
                targets.acknowledgement(
                    view,
                    prepared,
                    &current,
                    pending.acknowledged_through_sequence,
                    now_ms,
                )?;
            }
            if pending.high_water_sequence != 0 {
                targets.admission(
                    view,
                    prepared,
                    &current,
                    pending.high_water_sequence,
                    now_ms,
                )?;
            }
        }
        Subject::Acknowledged { record } => {
            let original = targets.admission(
                view,
                prepared,
                &current,
                record.outcome.binding.gateway_sequence,
                now_ms,
            )?;
            if original.record != *record {
                return Err(Error::Execution.into());
            }
            targets.acknowledgement(
                view,
                prepared,
                &current,
                record.outcome.binding.gateway_sequence,
                now_ms,
            )?;
        }
        Subject::Released { record } => {
            let original = targets.admission(
                view,
                prepared,
                &current,
                record.outcome.binding.gateway_sequence,
                now_ms,
            )?;
            if original.record != *record {
                return Err(Error::Execution.into());
            }
            let lease_id = record.lease_id.ok_or(Error::Execution)?;
            let rows = WorldGatewayRows::new(
                view.world(),
                &prepared.expected.network_id,
                prepared.expected.qualification.gateway_id,
            )
            .map_err(|_| Error::Execution)?;
            let Some(GatewayRow::LeaseTerminal(terminal)) = rows
                .read(&GatewayRowKey::LeaseTerminal(lease_id))
                .map_err(|_| Error::Execution)?
            else {
                return Err(Error::Execution.into());
            };
            if terminal.grant.sequence != record.outcome.binding.gateway_sequence
                || Some(terminal.grant.expires_at_unix_ms) != record.lease_expires_at_unix_ms
            {
                return Err(Error::Execution.into());
            }
            targets.policy(view, prepared, terminal.policy_revision)?;
            targets.charge(&terminal)?;
            targets.targets.push(Target {
                execution: terminal.execution.clone(),
                policy_revision: terminal.policy_revision,
                action: ExpectedAction::Terminal {
                    original: *record,
                    terminal,
                },
            });
        }
    }
    // Every historical claim must already belong to the pre-challenge captured floor.
    if targets.targets.iter().any(|target| {
        target.execution.height == 0 || target.execution.height > check_claim.floor.height
    }) {
        return Err(Error::Execution.into());
    }
    targets.targets.sort_by_key(|target| {
        (
            target.execution.height,
            target.execution.entry_index,
            target.execution.instruction_index,
        )
    });
    Ok(targets)
}

fn exact_source(
    target: &Target,
    policies: &BTreeMap<u64, GatewayPolicyRecordV1>,
    entry: &TransactionEntrypoint,
    prepared: &PreparedStreamTokenGatewayCheckV1,
    block_time: u64,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<Error>> {
    let execution = &target.execution;
    let TransactionEntrypoint::External(signed) = entry else {
        return Err(Error::Execution.into());
    };
    if let ExpectedAction::RecorderPolicy(record) = &target.action {
        use iroha_data_model::{
            isi::sorafs::SetSorafsReputationJournalAuthorityPolicy,
            sorafs::reputation::ReputationJournalPolicyOriginV1 as Origin,
        };
        record.validate().map_err(|_| Error::Execution)?;
        if execution != record.origin.execution()
            || signed.authority() != &record.activated_by
            || block_time != record.activated_at_unix_ms
            || *entry.hash().as_ref() != execution.transaction_hash
            || norito::canonical_frame_len(entry).map_err(|error| {
                crate::execution_attempt::norito_decode_attempt_error(error, |_| Error::Execution)
            })? > MAX_TARGET_BYTES
        {
            return Err(Error::Execution.into());
        }
        signed.verify_signature().map_err(|_| Error::Execution)?;
        let Executable::Instructions(items) = signed.instructions() else {
            return Err(Error::Execution.into());
        };
        match &record.origin {
            Origin::Genesis(_) if execution.height == 1 && signed.network_id().is_none() => {}
            Origin::Network(_)
                if execution.height > 1
                    && items.len() == 1
                    && execution.instruction_index == 0
                    && signed.network_id() == Some(&prepared.expected.network_id) => {}
            _ => return Err(Error::Execution.into()),
        }
        let original = items
            .get(usize::try_from(execution.instruction_index).map_err(|_| Error::Execution)?)
            .and_then(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<SetSorafsReputationJournalAuthorityPolicy>()
            })
            .ok_or(Error::Execution)?;
        return if original.policy == record.policy {
            Ok(())
        } else {
            Err(Error::Execution.into())
        };
    }
    native_signed_entry_frame_v1(entry)
        .map_err(|error| error.map_rejection(|_| Error::Execution))?;
    if signed.network_id() != Some(&prepared.expected.network_id)
        || signed.authority() != &execution.authority
        || *entry.hash().as_ref() != execution.transaction_hash
        || signed.hash_as_entrypoint() != entry.hash()
        || block_time != execution.recorded_at_unix_ms
    {
        return Err(Error::Execution.into());
    }
    if let ExpectedAction::ReputationAppend(source) = &target.action {
        let intent = source.intent.as_ref().ok_or(Error::Execution)?;
        intent.validate().map_err(|_| Error::Execution)?;
        if execution.instruction_index != 0
            || signed.payload() != &intent.payload
            || source.record.admitted_under.gateway_id != prepared.expected.qualification.gateway_id
            || source.record != intent.record
            || source.execution != intent.source_execution
            || source.recorder_policy != intent.recorder_policy
        {
            return Err(Error::Execution.into());
        }
        return Ok(());
    }
    let index = usize::try_from(execution.instruction_index).map_err(|_| Error::Execution)?;
    let instruction = match signed.instructions() {
        Executable::Instructions(items) => items.get(index),
        Executable::Batch(items) => items.get(index).and_then(|item| match item {
            ExecutableBatchItem::Instruction(instruction) => Some(instruction),
            ExecutableBatchItem::ContractCall(_) => None,
        }),
        Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => None,
    }
    .and_then(|item| {
        item.as_any()
            .downcast_ref::<MutateSorafsStreamTokenGateway>()
    })
    .ok_or(Error::Execution)?;
    instruction
        .request
        .validate()
        .map_err(|_| Error::Execution)?;
    let request = &instruction.request;
    if request.network_id != prepared.expected.network_id
        || request.gateway_id != prepared.expected.qualification.gateway_id
    {
        return Err(Error::Execution.into());
    }
    let policy = &policies
        .get(&target.policy_revision)
        .ok_or(Error::Execution)?
        .policy;
    if !matches!(target.action, ExpectedAction::Configure(_))
        && (request.expected_policy_revision != target.policy_revision
            || request.expected_policy_digest != policy.qualification.policy_digest
            || (!matches!(target.action, ExpectedAction::ReputationCancellation { .. })
                && !policy.operators.contains(&execution.authority)))
    {
        return Err(Error::Execution.into());
    }
    let matches = match (&target.action, &request.action) {
        (
            ExpectedAction::ReputationCancellation {
                original,
                recorder_policy_digest,
                reason,
            },
            Action::CancelReputationDelivery {
                record,
                expected_recorder_policy_digest,
                reason: actual_reason,
            },
        ) => {
            record == original
                && recorder_policy_digest == expected_recorder_policy_digest
                && reason == actual_reason
                && execution.instruction_index == 0
                && matches!(signed.instructions(), Executable::Instructions(items) if items.len() == 1)
        }

        (ExpectedAction::Configure(record), Action::Configure(policy)) => {
            policy == &record.policy
                && instruction_digest(instruction, signed.authority())
                    .map_err(|_| Error::Execution)?
                    == record.instruction_digest
        }
        (ExpectedAction::Admit(original), Action::Admit(request)) => request == &original.request,
        (ExpectedAction::Acknowledge(original), Action::Acknowledge(record)) => {
            record == &original.record
        }
        (ExpectedAction::Terminal { original, terminal }, Action::ReleaseLease(record)) => {
            !terminal.expired && record == original
        }
        (ExpectedAction::Terminal { terminal, .. }, Action::Expire { max_items }) => {
            terminal.expired
                && *max_items != 0
                && execution.recorded_at_unix_ms >= terminal.grant.expires_at_unix_ms
        }
        _ => false,
    };
    if !matches {
        return Err(Error::Execution.into());
    }
    Ok(())
}

fn authenticate_target(
    view: &StateView<'_>,
    prepared: &PreparedStreamTokenGatewayCheckV1,
    target: &Target,
    policies: &BTreeMap<u64, GatewayPolicyRecordV1>,
    block: &CertifiedBlock,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<Error>> {
    let execution = &target.execution;
    let entry_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::prehashed(
        execution.transaction_hash,
    ));
    if block.height() != execution.height
        || view
            .transactions
            .get(&entry_hash)
            .map(|height| height.get())
            != usize::try_from(execution.height).ok()
    {
        return Err(Error::Execution.into());
    }
    let anchor = block
        .entry_anchor(&entry_hash)
        .map_err(|_| Error::Execution)?;
    let body = block.block();
    let proof = body
        .network_execution_proof(&entry_hash)
        .ok_or(Error::Execution)?;
    if !proof.verify(&anchor) || anchor.entry_index() != execution.entry_index {
        return Err(Error::Execution.into());
    }
    let entry = body
        .network_entrypoint_at(
            usize::try_from(execution.entry_index).map_err(|_| Error::Execution)?,
        )
        .ok_or(Error::Execution)?;
    let (_, output) = body
        .network_output_at(execution.entry_index)
        .ok_or(Error::Execution)?;
    if !output.result.is_ok() {
        return Err(Error::Execution.into());
    }
    exact_source(target, policies, entry, prepared, block.block_time_ms())
}

pub(super) fn authenticate<'view, 'state, 'bound>(
    view: &'view StateView<'state>,
    prepared: &PreparedStreamTokenGatewayCheckV1,
    bound: &'bound mut Option<BoundNativeCheckV1>,
) -> Result<
    BorrowedCheckExecutionCutV1<'view, 'state, 'bound>,
    crate::execution_attempt::ExecutionAttemptError<Error>,
> {
    crate::query::signer_check::with_native_check_read_limits(|| {
        let mut check = PreparedCheckExecutionV1::new(
            view,
            NativeCustodyCheckPurposeV1::StreamTokenGateway,
            bound,
            &prepared.round,
        )
        .map_err(|error| error.map_rejection(Error::from))?;
        let targets = prepare_targets(view, prepared)?;
        let start = targets
            .targets
            .first()
            .map(|target| target.execution.height)
            .unwrap_or_else(|| check.floor_height())
            .min(check.floor_height());
        let through = if start == 1 {
            check.applied_height().max(2)
        } else {
            check.applied_height()
        };
        if through != check.applied_height() {
            return Err(Error::Finality.into());
        }
        let chain =
            SignerCertifiedWalkV1::new(view).map_err(|error| error.map_rejection(Error::from))?;
        let mut cursor = 0;
        let mut finality_bytes = 0usize;
        let mut next_height = Some(start);
        for block in chain.walk(start, through) {
            prepared.round.ensure_live().map_err(Error::from)?;
            let receipt = block.map_err(|error| error.map_rejection(Error::from))?;
            let block = receipt.in_view(view).map_err(Error::from)?;
            if next_height != Some(block.height())
                || (block.height() > 1 && block.verification() != QcVerification::Verified)
            {
                return Err(Error::Finality.into());
            }
            finality_bytes = finality_bytes
                .checked_add(block.certificate_len())
                .filter(|total| *total <= MAX_FINALITY_BYTES)
                .ok_or_else(|| {
                    crate::execution_attempt::ExecutionAttemptError::Deferred(
                        ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                    )
                })?;
            while let Some(target) = targets.targets.get(cursor)
                && target.execution.height == block.height()
            {
                authenticate_target(view, prepared, target, &targets.policies, block)?;
                cursor += 1;
            }
            if block.height() >= check.floor_height() {
                check
                    .consume(&receipt)
                    .map_err(|error| error.map_rejection(Error::from))?;
            }
            next_height = if block.height() == through {
                None
            } else {
                block.height().checked_add(1)
            };
        }
        if next_height.is_some() || cursor != targets.targets.len() {
            return Err(Error::Finality.into());
        }
        prepared.round.ensure_live().map_err(Error::from)?;
        check
            .finish()
            .map_err(|error| error.map_rejection(Error::from))
    })
}
