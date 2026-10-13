//! Native source-owned immutable append custody and authenticated terminal disposition.
//!
//! Every writer prepares bounded canonical bytes and all checks before publishing. Missing local
//! custody never authorizes first signing: only the original committed source owns that recipe.

use super::*;
use crate::query::stream_token_gateway::{
    rows::{
        AdmissionRowV1, GatewayRow, GatewayRowKey, GatewayRows, TransitionDelta, TransitionResult,
    },
    storage::{STATE_ROOT, WorldGatewayRows},
    transition::request_digest,
};
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    sorafs::{
        reputation::stream_token_delivery::{
            STREAM_TOKEN_REPUTATION_MAX_INTENT_BYTES_V1,
            StreamTokenReputationCancellationReasonV1 as CancelReason,
            StreamTokenReputationDeliveryDispositionV1 as Disposition,
            StreamTokenReputationDeliveryIntentV1 as Intent,
        },
        stream_token_gateway::{
            StreamTokenGatewayAdmissionRecordV1 as Record,
            native::StreamTokenGatewayExecutionV1 as Execution,
        },
    },
    transaction::{TransactionBuilder, TransactionPayload},
};

/// Immutable exact native source with an optional counted recipe; Excluded owns no append.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_reputation::stream_token_delivery::Source"
)]
pub(crate) struct Source {
    /// Exact original source, including the serving attempt.
    pub(crate) record: Record,
    /// Full original request commitment from the permanent context index.
    pub(crate) request_digest: [u8; 32],
    /// Original direct Admit execution.
    pub(crate) execution: Execution,
    /// Source-time recorder policy whose interval cannot later be reassigned.
    pub(crate) recorder_policy: ReputationJournalAuthorityPolicyRecordV1,
    /// Present exactly for counted statuses; absence is not an authorization to create one.
    pub(crate) intent: Option<Intent>,
}
/// A source-bound explicit Pending/terminal fact, independent of local delivery custody.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_reputation::stream_token_delivery::State"
)]
pub(crate) struct DeliveryState {
    /// Exact immutable source commitment, not a caller-supplied claim of authority.
    pub(crate) source_digest: [u8; 32],
    /// Explicit current state. Only Pending may become one terminal fact.
    pub(crate) disposition: Disposition,
}
/// Fully prepared native writes; publication has no fallible work or external callbacks.
#[derive(Default)]
pub(crate) struct Prepared {
    writes: Vec<(StatePath, Vec<u8>)>,
}
impl Prepared {
    /// Publish into the same World overlay as the already prepared gateway mutation.
    pub(crate) fn publish(self, tx: &mut StateTransaction<'_, '_>) {
        for (key, bytes) in self.writes {
            tx.world.smart_contract_state.insert(key, bytes);
        }
    }
}
fn path(
    gateway: [u8; 32],
    sequence: u64,
    leaf: &str,
) -> Result<StatePath, InstructionExecutionError> {
    if gateway == [0; 32] || sequence == 0 {
        return Err(corrupt_state("invalid delivery source key"));
    }
    StatePath::from_str(&format!(
        "{STATE_ROOT}/{}/reputation/{sequence:020}/{leaf}",
        hex::encode(gateway)
    ))
    .map_err(|_| corrupt_state("invalid delivery source path"))
}
fn watermark_path() -> Result<StatePath, InstructionExecutionError> {
    StatePath::from_str(&format!("{STATE_ROOT}/reputation_source_time_watermark"))
        .map_err(|_| corrupt_state("invalid delivery watermark path"))
}
fn encode_delivery<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<Vec<u8>, InstructionExecutionError> {
    let bytes = encode_state(value, label)?;
    if bytes.len() > STREAM_TOKEN_REPUTATION_MAX_INTENT_BYTES_V1 {
        return Err(corrupt_state(
            "native delivery row exceeds its bounded frame",
        ));
    }
    Ok(bytes)
}
fn decode_delivery<T>(bytes: &[u8], label: &str) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.len() > STREAM_TOKEN_REPUTATION_MAX_INTENT_BYTES_V1 {
        return Err(corrupt_state(
            "native delivery row exceeds its bounded frame",
        ));
    }
    decode_state(bytes, label)
}
fn source_digest(source: &Source) -> Result<[u8; 32], InstructionExecutionError> {
    let bytes =
        norito::encode_canonical(source).map_err(|_| corrupt_state("delivery source encoding"))?;
    if bytes.len() > STREAM_TOKEN_REPUTATION_MAX_INTENT_BYTES_V1 {
        return Err(invalid_parameter(
            "native delivery source exceeds its canonical byte bound",
        ));
    }
    let mut material = b"iroha.sorafs.token-reputation.source.v1\0".to_vec();
    material.extend_from_slice(&bytes);
    Ok(*Hash::new(material).as_ref())
}
/// The maximum observed source time is protocol State, never a daemon clock or file counter.
pub(crate) fn source_time_watermark(
    world: &impl WorldReadOnly,
) -> Result<Option<u64>, InstructionExecutionError> {
    world
        .smart_contract_state()
        .get(&watermark_path()?)
        .map(|bytes| decode_state::<u64>(bytes, "native reputation source-time watermark"))
        .transpose()?
        .map(|value| {
            if value == 0 || value == u64::MAX {
                Err(corrupt_state(
                    "invalid native reputation source-time watermark",
                ))
            } else {
                Ok(value)
            }
        })
        .transpose()
}
fn same_source(
    source: &Source,
    original: &AdmissionRowV1,
) -> Result<(), InstructionExecutionError> {
    if source.record != original.record
        || source.execution != original.execution
        || source.request_digest
            != request_digest(&original.request)
                .map_err(|_| corrupt_state("invalid original gateway request"))?
    {
        return Err(corrupt_state(
            "native reputation source differs from original admission",
        ));
    }
    Ok(())
}
fn expected_entry(
    source: &Source,
) -> Result<Option<ReputationJournalEntryV1>, InstructionExecutionError> {
    match &source.intent {
        None if !source.record.outcome.status.counts_for_provider() => Ok(None),
        Some(intent) if source.record.outcome.status.counts_for_provider() => {
            intent
                .validate()
                .map_err(|_| corrupt_state("invalid retained native delivery intent"))?;
            if (
                &intent.record,
                &intent.request_digest,
                &intent.source_execution,
                &intent.recorder_policy,
            ) != (
                &source.record,
                &source.request_digest,
                &source.execution,
                &source.recorder_policy,
            ) {
                return Err(corrupt_state(
                    "native delivery intent substitutes its source",
                ));
            }
            let iroha_data_model::transaction::Executable::Instructions(items) =
                &intent.payload.instructions
            else {
                return Err(corrupt_state("native delivery payload is not one append"));
            };
            if items.len() != 1 {
                return Err(corrupt_state(
                    "native delivery payload has extra instructions",
                ));
            }
            items[0]
                .as_any()
                .downcast_ref::<AppendSorafsStreamTokenReputationJournalEntry>()
                .map(|instruction| Some(instruction.entry.clone()))
                .ok_or_else(|| corrupt_state("native delivery payload is not its exact append"))
        }
        _ => Err(corrupt_state(
            "counted and excluded native delivery material differ",
        )),
    }
}
fn position(execution: &Execution) -> (u64, u32, u32) {
    (
        execution.height,
        execution.entry_index,
        execution.instruction_index,
    )
}
fn validate_terminal_execution(
    source: &Source,
    execution: &Execution,
) -> Result<(), InstructionExecutionError> {
    if execution.height == 0
        || execution.transaction_hash == [0; 32]
        || execution.recorded_at_unix_ms == u64::MAX
        || execution.recorded_at_unix_ms < source.execution.recorded_at_unix_ms
        || position(execution) < position(&source.execution)
    {
        return Err(corrupt_state(
            "delivery terminal precedes or substitutes original source",
        ));
    }
    Ok(())
}
/// Load an immutable source-bound recorder policy for a bounded signed-history proof target.
pub(crate) fn read_policy(
    world: &impl WorldReadOnly,
    digest: [u8; 32],
) -> Result<ReputationJournalAuthorityPolicyRecordV1, InstructionExecutionError> {
    let policy = read_policy_history(world, &digest)?
        .ok_or_else(|| corrupt_state("recorder policy history missing"))?;
    validate_policy_predecessor(world, &policy)?;
    policy
        .validate()
        .map_err(|_| corrupt_state("recorder policy history invalid"))?;
    Ok(policy)
}
/// Read exact source/disposition and native journal association from one World; not a finality proof.
pub(crate) fn read(
    world: &impl WorldReadOnly,
    network: &NetworkId,
    record: &Record,
) -> Result<(Source, DeliveryState), InstructionExecutionError> {
    let gateway = record.admitted_under.gateway_id;
    let sequence = record.outcome.binding.gateway_sequence;
    let original = WorldGatewayRows::new(world, network, gateway)
        .map_err(|_| corrupt_state("gateway delivery source unavailable"))?
        .read(&GatewayRowKey::Admission(sequence))
        .map_err(|_| corrupt_state("gateway delivery source invalid"))?;
    let Some(GatewayRow::Admission(original)) = original else {
        return Err(corrupt_state("native delivery has no original admission"));
    };
    if original.record != *record {
        return Err(invalid_parameter("delivery record was substituted"));
    }
    let source: Source = decode_delivery(
        world
            .smart_contract_state()
            .get(&path(gateway, sequence, "source")?)
            .ok_or_else(|| {
                corrupt_state("native admission is missing permanent delivery source")
            })?,
        "native delivery source",
    )?;
    same_source(&source, &original)?;
    let active = read_active_policy(world)?
        .ok_or_else(|| corrupt_state("native delivery policy missing"))?;
    if read_policy_at_source_time(
        world,
        active,
        source.recorder_policy.policy_digest,
        record.outcome.validated_at_unix_ms,
    )? != source.recorder_policy
    {
        return Err(corrupt_state(
            "native delivery source-time policy was substituted",
        ));
    }
    if source_time_watermark(world)?
        .is_none_or(|watermark| watermark < record.outcome.validated_at_unix_ms)
    {
        return Err(corrupt_state(
            "native delivery source-time watermark regressed",
        ));
    }
    let state: DeliveryState = decode_delivery(
        world
            .smart_contract_state()
            .get(&path(gateway, sequence, "state")?)
            .ok_or_else(|| corrupt_state("native delivery disposition missing"))?,
        "native delivery state",
    )?;
    if state.source_digest != source_digest(&source)? {
        return Err(corrupt_state("native delivery source digest mismatch"));
    }
    let entry = expected_entry(&source)?;
    let journal_sequence = match &entry {
        Some(entry) => exact_entry_replay(world, entry)?,
        None => {
            let source_id =
                ReputationJournalPayloadV1::StreamTokenValidation(record.outcome).source_id();
            if read_source_head(world, source_id)?.is_some() {
                return Err(corrupt_state(
                    "excluded source unexpectedly occupies the journal",
                ));
            }
            None
        }
    };
    match (&state.disposition, entry.as_ref(), source.intent.as_ref()) {
        (Disposition::Pending, Some(_), Some(_)) if journal_sequence.is_none() => {}
        (Disposition::Excluded, None, None) => {}
        (
            Disposition::Delivered {
                journal_sequence: expected,
                event_id,
                execution,
            },
            Some(entry),
            Some(intent),
        ) => {
            validate_terminal_execution(&source, execution)?;
            let actual = read_event(world, *expected)?
                .ok_or_else(|| corrupt_state("delivered journal event missing"))?;
            let builder = TransactionBuilder::from_payload(intent.payload.clone())
                .map_err(|_| corrupt_state("invalid retained append payload"))?;
            if journal_sequence != Some(*expected)
                || entry.event_id != *event_id
                || actual.entry != *entry
                || actual.target_block_height != execution.height
                || actual.recorded_at_unix_ms != execution.recorded_at_unix_ms
                || execution.transaction_hash != *builder.hash_as_entrypoint().as_ref()
                || execution.authority != entry.recorded_by
                || execution.instruction_index != 0
                || intent
                    .expired_at(execution.height, execution.recorded_at_unix_ms)
                    .map_err(|_| corrupt_state("invalid delivery lifetime"))?
            {
                return Err(corrupt_state("delivered journal provenance mismatch"));
            }
        }
        (Disposition::Expired { execution }, Some(_), Some(intent))
            if journal_sequence.is_none() =>
        {
            validate_terminal_execution(&source, execution)?;
            if !intent
                .expired_at(execution.height, execution.recorded_at_unix_ms)
                .map_err(|_| corrupt_state("invalid delivery lifetime"))?
            {
                return Err(corrupt_state(
                    "native delivery expired before its original deadline",
                ));
            }
        }
        (
            Disposition::GovernanceCancelled {
                recorder_policy_digest,
                gateway_qualification,
                execution,
                ..
            },
            Some(_),
            Some(_),
        ) if journal_sequence.is_none() => {
            validate_terminal_execution(&source, execution)?;
            let policy = read_policy(world, *recorder_policy_digest)?;
            let gateway_policy = crate::query::stream_token_gateway::storage::read_policy_record(
                world,
                network,
                gateway,
                gateway_qualification.revision,
            )
            .map_err(|_| corrupt_state("cancellation gateway policy history missing"))?;
            if gateway_policy.policy.qualification != *gateway_qualification
                || gateway_qualification.gateway_id != gateway
                || gateway_qualification.revision < record.admitted_under.revision
                || position(&gateway_policy.execution) > position(execution)
                || gateway_policy.execution.recorded_at_unix_ms > execution.recorded_at_unix_ms
            {
                return Err(corrupt_state("cancellation gateway policy was substituted"));
            }
            if policy.activated_at_unix_ms > execution.recorded_at_unix_ms {
                return Err(corrupt_state("cancellation policy postdates cancellation"));
            }
        }
        _ => return Err(corrupt_state("native delivery state and journal disagree")),
    }
    Ok((source, state))
}

/// Prepare every new source and watermark before either gateway or reputation rows are published.
pub(crate) fn prepare_admission(
    tx: &StateTransaction<'_, '_>,
    delta: &TransitionDelta,
) -> Result<Prepared, InstructionExecutionError> {
    let mut prepared = Prepared::default();
    if let TransitionResult::Admission(result) = &delta.result {
        if delta.writes.is_empty() {
            // Exact replay must retain the original source; absence never permits rebuilding it.
            read(tx.world(), tx.network_id(), &result.record)?;
        }
    }
    let mut watermark = source_time_watermark(tx.world())?.unwrap_or(0);
    for write in &delta.writes {
        let Some(GatewayRow::Admission(original)) = &write.after else {
            continue;
        };
        if write.before.is_some() {
            return Err(corrupt_state("native admission source replacement"));
        }
        let record = original.record;
        let gateway = record.admitted_under.gateway_id;
        let sequence = record.outcome.binding.gateway_sequence;
        let source_key = path(gateway, sequence, "source")?;
        let state_key = path(gateway, sequence, "state")?;
        if tx.world.smart_contract_state.get(&source_key).is_some()
            || tx.world.smart_contract_state.get(&state_key).is_some()
        {
            return Err(corrupt_state(
                "new native admission already has delivery history",
            ));
        }
        let active = read_active_policy(tx.world())?
            .ok_or_else(|| invalid_parameter("reputation recorder policy not configured"))?;
        // Source time selects an already configured historical policy; no local callback clock.
        let mut selected = active.clone();
        let mut traversed = 0usize;
        while selected.activated_at_unix_ms > record.outcome.validated_at_unix_ms {
            traversed += 1;
            if traversed > REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1 {
                return Err(corrupt_state(
                    "delivery policy history exceeds native bound",
                ));
            }
            validate_policy_predecessor(tx.world(), &selected)?;
            let predecessor = selected
                .policy
                .predecessor_policy_digest
                .ok_or_else(|| invalid_parameter("source predates governed reputation policy"))?;
            selected = read_policy_history(tx.world(), &predecessor)?
                .ok_or_else(|| corrupt_state("recorder policy predecessor missing"))?;
        }
        let selected = read_policy_at_source_time(
            tx.world(),
            active,
            selected.policy_digest,
            record.outcome.validated_at_unix_ms,
        )?;
        let digest = request_digest(&original.request)
            .map_err(|_| invalid_parameter("invalid gateway request digest"))?;
        let intent = if record.outcome.status.counts_for_provider() {
            validate_provider_binding(tx.world(), record.provider_id)?;
            require_permission(
                tx,
                &selected.policy.token_recorder_authority,
                CAN_RECORD_ENTRY,
            )?;
            Some(
                Intent::derive(
                    *tx.network_id(),
                    record,
                    digest,
                    original.execution.clone(),
                    selected.clone(),
                    tx.world
                        .parameters
                        .get()
                        .transaction()
                        .max_time_to_live_ms()
                        .get(),
                )
                .map_err(|_| invalid_parameter("native stream-token delivery recipe refused"))?,
            )
        } else {
            None
        };
        let source = Source {
            record,
            request_digest: digest,
            execution: original.execution.clone(),
            recorder_policy: selected,
            intent,
        };
        let state = DeliveryState {
            source_digest: source_digest(&source)?,
            disposition: if source.intent.is_some() {
                Disposition::Pending
            } else {
                Disposition::Excluded
            },
        };
        watermark = watermark.max(record.outcome.validated_at_unix_ms);
        prepared.writes.push((
            source_key,
            encode_delivery(&source, "native delivery source")?,
        ));
        prepared
            .writes
            .push((state_key, encode_delivery(&state, "native delivery state")?));
    }
    if !prepared.writes.is_empty() {
        prepared.writes.push((
            watermark_path()?,
            encode_state(&watermark, "native delivery watermark")?,
        ));
    }
    Ok(prepared)
}

/// Prepare exact ordered acknowledgement; only authenticated expiry may terminalize Pending.
pub(crate) fn prepare_acknowledgement(
    tx: &StateTransaction<'_, '_>,
    record: &Record,
    execution: &Execution,
) -> Result<(Prepared, DeliveryState), InstructionExecutionError> {
    let (source, mut state) = read(tx.world(), tx.network_id(), record)?;
    let mut prepared = Prepared::default();
    if state.disposition == Disposition::Pending {
        if !source
            .intent
            .as_ref()
            .ok_or_else(|| corrupt_state("pending source intent missing"))?
            .expired_at(execution.height, execution.recorded_at_unix_ms)
            .map_err(|_| corrupt_state("invalid pending delivery lifetime"))?
        {
            return Err(invalid_parameter(
                "live pending reputation delivery cannot be acknowledged",
            ));
        }
        state.disposition = Disposition::Expired {
            execution: execution.clone(),
        };
        prepared.writes.push((
            path(
                record.admitted_under.gateway_id,
                record.outcome.binding.gateway_sequence,
                "state",
            )?,
            encode_delivery(&state, "expired native delivery state")?,
        ));
    }
    Ok((prepared, state))
}

/// Prepare an explicit current-policy-manager cancellation; an existing Delivered wins unchanged.
pub(crate) fn prepare_cancellation(
    tx: &StateTransaction<'_, '_>,
    authority: &AccountId,
    record: &Record,
    expected_policy_digest: [u8; 32],
    reason: CancelReason,
    execution: &Execution,
    gateway_qualification: iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionQualificationV1,
) -> Result<Prepared, InstructionExecutionError> {
    require_permission(tx, authority, CAN_MANAGE_POLICY)?;
    let active = read_active_policy(tx.world())?
        .ok_or_else(|| invalid_parameter("recorder policy unavailable"))?;
    if active.policy_digest != expected_policy_digest {
        return Err(invalid_parameter(
            "cancellation recorder policy CAS mismatch",
        ));
    }
    let (_, mut state) = read(tx.world(), tx.network_id(), record)?;
    let mut prepared = Prepared::default();
    match &state.disposition {
        Disposition::Pending => {
            state.disposition = Disposition::GovernanceCancelled {
                recorder_policy_digest: expected_policy_digest,
                gateway_qualification,
                reason,
                execution: execution.clone(),
            };
            prepared.writes.push((
                path(
                    record.admitted_under.gateway_id,
                    record.outcome.binding.gateway_sequence,
                    "state",
                )?,
                encode_delivery(&state, "cancelled native delivery state")?,
            ));
        }
        Disposition::Delivered { .. } => {}
        Disposition::GovernanceCancelled {
            recorder_policy_digest,
            reason: original,
            ..
        } if *recorder_policy_digest == expected_policy_digest && *original == reason => {}
        _ => {
            return Err(invalid_parameter(
                "native reputation delivery already terminal",
            ));
        }
    }
    Ok(prepared)
}

/// Enforce one exact directly signed original append payload before native journal mutation.
pub(crate) fn execute_append(
    tx: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    entry: ReputationJournalEntryV1,
) -> Result<(), InstructionExecutionError> {
    let payload: TransactionPayload = tx
        .current_direct_stream_token_reputation_payload
        .take()
        .ok_or_else(|| {
            invalid_parameter("stream-token append requires its sole exact external payload")
        })?;
    require_permission(tx, authority, CAN_RECORD_ENTRY)?;
    let ReputationJournalPayloadV1::StreamTokenValidation(outcome) = &entry.payload else {
        return Err(invalid_parameter(
            "stream-token append source kind mismatch",
        ));
    };
    let rows = WorldGatewayRows::new(tx.world(), tx.network_id(), outcome.binding.gateway_id)
        .map_err(|_| corrupt_state("append gateway source unavailable"))?;
    let Some(GatewayRow::Admission(original)) = rows
        .read(&GatewayRowKey::Admission(outcome.binding.gateway_sequence))
        .map_err(|_| corrupt_state("append gateway source invalid"))?
    else {
        return Err(invalid_parameter(
            "append requires a committed native gateway source",
        ));
    };
    let (source, mut state) = read(tx.world(), tx.network_id(), &original.record)?;
    let intent = source
        .intent
        .as_ref()
        .ok_or_else(|| invalid_parameter("excluded native source cannot append"))?;
    if expected_entry(&source)?.as_ref() != Some(&entry)
        || payload != intent.payload
        || &payload.authority != authority
    {
        return Err(invalid_parameter(
            "append differs from immutable native source payload",
        ));
    }
    let builder = TransactionBuilder::from_payload(payload)
        .map_err(|_| invalid_parameter("invalid append payload"))?;
    let outer = builder.hash_as_entrypoint();
    if tx.current_network_entrypoint_hash != Some(outer)
        || tx.tx_call_hash != Some(Hash::from(outer))
        || tx.current_tx_hash.is_none()
    {
        return Err(invalid_parameter("append external source binding mismatch"));
    }
    if matches!(state.disposition, Disposition::Delivered { .. }) {
        return Ok(());
    }
    if state.disposition != Disposition::Pending {
        return Err(invalid_parameter(
            "terminal native intent forbids late append",
        ));
    }
    let execution = Execution {
        height: tx._curr_block.height().get(),
        transaction_hash: *outer.as_ref(),
        entry_index: tx
            .current_entrypoint_index
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| invalid_parameter("append entry coordinate missing"))?,
        instruction_index: 0,
        recorded_at_unix_ms: block_time_ms(tx)?,
        authority: authority.clone(),
    };
    if intent
        .expired_at(execution.height, execution.recorded_at_unix_ms)
        .map_err(|_| invalid_parameter("invalid original append lifetime"))?
    {
        return Err(invalid_parameter("original append lifetime expired"));
    }
    validate_new_entry(
        tx,
        authority,
        &entry,
        ReputationJournalSourceKindV1::StreamToken,
    )?;
    let journal = prepare_validated_entry(tx, entry.clone())?;
    state.disposition = Disposition::Delivered {
        journal_sequence: journal.sequence,
        event_id: entry.event_id,
        execution,
    };
    let key = path(
        original.record.admitted_under.gateway_id,
        original.record.outcome.binding.gateway_sequence,
        "state",
    )?;
    let bytes = encode_delivery(&state, "delivered native reputation state")?;
    // All source, journal, disposition and bounded encoding checks finish before publication.
    journal.publish(tx);
    tx.world.smart_contract_state.insert(key, bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_rows_are_bounded_before_decoding_and_reject_trailing_bytes() {
        let row = DeliveryState {
            source_digest: [7; 32],
            disposition: Disposition::Pending,
        };
        let frame = encode_delivery(&row, "fixture").unwrap();
        assert_eq!(
            decode_delivery::<DeliveryState>(&frame, "fixture").unwrap(),
            row
        );
        let mut trailing = frame;
        trailing.push(0);
        assert!(decode_delivery::<DeliveryState>(&trailing, "fixture").is_err());
        assert!(
            decode_delivery::<DeliveryState>(
                &vec![0; STREAM_TOKEN_REPUTATION_MAX_INTENT_BYTES_V1 + 1],
                "fixture"
            )
            .is_err()
        );
        assert!(
            encode_delivery(
                &vec![0u8; STREAM_TOKEN_REPUTATION_MAX_INTENT_BYTES_V1 + 1],
                "fixture"
            )
            .is_err()
        );
    }
}
