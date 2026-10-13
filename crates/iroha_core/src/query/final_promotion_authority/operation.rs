//! Bounded immutable operation history and exact spent-identity lookup.
use super::*;
use iroha_data_model::sorafs::final_promotion_authority::{
    FINAL_PROMOTION_OPERATION_RECORD_DOMAIN_V1, FINAL_PROMOTION_RESERVATION_MS_V1,
};
use sorafs_manifest::signer::protocol::SignerOperationActionV1;

pub(crate) fn operation_digest(
    record: &FinalPromotionOperationRecordV1,
) -> Result<[u8; 32], Error> {
    digest(FINAL_PROMOTION_OPERATION_RECORD_DOMAIN_V1, record)
}
fn read_basic(
    world: &impl WorldReadOnly,
    deployment: &str,
    revision: u64,
) -> Result<NativeOperation, Error> {
    let record: FinalPromotionOperationRecordV1 = decode(
        world
            .smart_contract_state()
            .get(&operation_record_key(deployment, revision)?)
            .ok_or(Error::CorruptHistory)?,
    )
    .map_err(|_| Error::CorruptHistory)?;
    if record.deployment_id != deployment
        || record.revision != revision
        || revision == 0
        || revision > FINAL_PROMOTION_MAX_OPERATIONS_V1 * 2
        || (revision == 1) != (record.predecessor_digest == [0; 32])
        || record.request_digest == [0; 32]
        || record.reserved_origin.entry_hash == [0; 32]
        || matches!(record.outcome, FinalPromotionOperationOutcomeV1::Reserved)
            && record.execution_origin != Some(record.reserved_origin)
        || matches!(
            record.outcome,
            FinalPromotionOperationOutcomeV1::Completed(_)
        ) && record
            .execution_origin
            .is_none_or(|origin| origin.entry_hash == [0; 32])
        || matches!(
            record.outcome,
            FinalPromotionOperationOutcomeV1::Expired
                | FinalPromotionOperationOutcomeV1::Invalidated
        ) && record.execution_origin.is_some()
        || !valid_execution(&record.execution)
        || !valid_execution(&record.reserved)
        || record.intent.digest().is_err()
        || record.intent.action != SignerOperationActionV1::Sign
        || record.custody.record_digest == [0; 32]
        || record.custody.control_state_digest == [0; 32]
        || record.reservation.reservation_id == [0; 32]
        || record.reservation.fence == 0
        || record.reservation.expires_at_unix_ms <= record.reserved.recorded_at_unix_ms
        || record
            .reserved
            .recorded_at_unix_ms
            .checked_add(FINAL_PROMOTION_RESERVATION_MS_V1)
            .is_none_or(|limit| record.reservation.expires_at_unix_ms > limit)
        || record.reservation.expires_at_unix_ms == u64::MAX
    {
        return Err(Error::CorruptHistory);
    }
    let index: OperationIndexV1 = decode(
        world
            .smart_contract_state()
            .get(&operation_height_key(
                deployment,
                record.execution.height,
                record.execution.ordinal,
            )?)
            .ok_or(Error::CorruptHistory)?,
    )
    .map_err(|_| Error::CorruptHistory)?;
    if index.height != record.execution.height
        || index.ordinal != record.execution.ordinal
        || index.head.revision != revision
        || index.head.digest != operation_digest(&record)?
    {
        return Err(Error::CorruptHistory);
    }
    Ok(NativeOperation { record, index })
}
pub(crate) fn successor_head(
    previous: FinalPromotionOperationHeadV1,
    old: Option<&FinalPromotionOperationRecordV1>,
    record: &FinalPromotionOperationRecordV1,
) -> Result<FinalPromotionOperationHeadV1, Error> {
    if previous.revision.checked_add(1) != Some(record.revision)
        || record.predecessor_digest != previous.digest
        || record.reserved_origin.entry_hash == [0; 32]
    {
        return Err(Error::CorruptHistory);
    }
    if let Some(old) = old {
        adjacent_execution(&old.execution, &record.execution)?;
    } else if record.execution.ordinal != 0 {
        return Err(Error::CorruptHistory);
    }
    let mut head = previous;
    head.revision = record.revision;
    head.digest = operation_digest(record)?;
    match record.outcome {
        FinalPromotionOperationOutcomeV1::Reserved => {
            if previous.active_operation.is_some()
                || record.reserved != record.execution
                || record.execution_origin != Some(record.reserved_origin)
                || record.intent.previous_audit != previous.audit
                || previous.fence.checked_add(1) != Some(record.reservation.fence)
            {
                return Err(Error::CorruptHistory);
            }
            head.fence = record.reservation.fence;
            head.total_admissions = previous
                .total_admissions
                .checked_add(1)
                .ok_or(Error::Capacity)?;
            if head.total_admissions > FINAL_PROMOTION_MAX_OPERATIONS_V1 {
                return Err(Error::Capacity);
            }
            head.active_operation = Some(record.intent.operation_id);
        }
        _ => {
            let old = old.ok_or(Error::CorruptHistory)?;
            if old.outcome != FinalPromotionOperationOutcomeV1::Reserved
                || previous.active_operation != Some(record.intent.operation_id)
                || record.intent != old.intent
                || record.custody != old.custody
                || record.reservation != old.reservation
                || record.reserved != old.reserved
                || record.reserved_origin != old.reserved_origin
            {
                return Err(Error::CorruptHistory);
            }
            head.active_operation = None;
            match record.outcome {
                FinalPromotionOperationOutcomeV1::Completed(completed) => {
                    if record
                        .execution_origin
                        .is_none_or(|origin| origin.entry_hash == [0; 32])
                    {
                        return Err(Error::CorruptHistory);
                    }
                    let commitment = completed.commitment;
                    let signatures_digest = completed.signatures_digest;
                    let execution_expired = record.execution.recorded_at_unix_ms
                        >= record.reservation.expires_at_unix_ms;
                    if record.execution.authority != record.reserved.authority
                        || record.execution.height <= record.reserved.height
                        || execution_expired
                        || previous.audit.sequence.checked_add(1) != Some(commitment.audit.sequence)
                        || commitment.audit.digest == [0; 32]
                        || commitment.audit.digest == previous.audit.digest
                        || commitment.response_digest == [0; 32]
                        || signatures_digest == [0; 32]
                    {
                        return Err(Error::CorruptHistory);
                    }
                    head.audit = commitment.audit;
                }
                FinalPromotionOperationOutcomeV1::Expired => {
                    if record.execution_origin.is_some() {
                        return Err(Error::CorruptHistory);
                    }
                    if record.execution.recorded_at_unix_ms < record.reservation.expires_at_unix_ms
                    {
                        return Err(Error::CorruptHistory);
                    }
                }
                FinalPromotionOperationOutcomeV1::Invalidated => {
                    if record.execution_origin.is_some() {
                        return Err(Error::CorruptHistory);
                    }
                }
                FinalPromotionOperationOutcomeV1::Reserved => return Err(Error::CorruptHistory),
            }
        }
    }
    if head.fence != head.total_admissions
        || head.audit.sequence > head.total_admissions
        || (head.audit.sequence == 0) != (head.audit.digest == [0; 32])
    {
        return Err(Error::CorruptHistory);
    }
    Ok(head)
}
pub(crate) fn read_operation_record(
    world: &impl WorldReadOnly,
    deployment: &str,
    revision: u64,
) -> Result<NativeOperation, Error> {
    let next = read_basic(world, deployment, revision)?;
    let previous = if revision > 1 {
        Some(read_basic(world, deployment, revision - 1)?)
    } else {
        None
    };
    let head = previous
        .as_ref()
        .map_or(FinalPromotionOperationHeadV1::empty(), |row| row.index.head);
    if successor_head(head, previous.as_ref().map(|row| &row.record), &next.record)?
        != next.index.head
    {
        return Err(Error::CorruptHistory);
    }
    Ok(next)
}
pub(crate) fn read_operation_head(
    world: &impl WorldReadOnly,
    deployment: &str,
) -> Result<FinalPromotionOperationHeadV1, Error> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&operation_head_key(deployment)?)
    else {
        if prefix_has_any(world, deployment, "operation_revision_")?
            || prefix_has_any(world, deployment, "operation_height_")?
            || prefix_has_any(world, deployment, "operation_id_")?
            || prefix_has_any(world, deployment, "operation_admission_")?
        {
            return Err(Error::CorruptHistory);
        }
        return Ok(FinalPromotionOperationHeadV1::empty());
    };
    let head: FinalPromotionOperationHeadV1 = decode(bytes).map_err(|_| Error::CorruptHistory)?;
    let row = read_operation_record(world, deployment, head.revision)?;
    if head != row.index.head {
        return Err(Error::CorruptHistory);
    }
    let latest_revision = world
        .smart_contract_state()
        .range(operation_record_key(deployment, 0)?..=operation_record_key(deployment, u64::MAX)?)
        .next_back();
    let latest_height = world
        .smart_contract_state()
        .range(
            operation_height_key(deployment, 0, 0)?
                ..=operation_height_key(deployment, u64::MAX, u32::MAX)?,
        )
        .next_back();
    if latest_revision.map(|(key, _)| key)
        != Some(&operation_record_key(deployment, head.revision)?)
        || latest_height.map(|(key, _)| key)
            != Some(&operation_height_key(
                deployment,
                row.index.height,
                row.index.ordinal,
            )?)
    {
        return Err(Error::CorruptHistory);
    }
    let slot: OperationIndexV1 = decode(
        world
            .smart_contract_state()
            .get(&operation_slot_key(
                deployment,
                row.record.intent.operation_id,
            )?)
            .ok_or(Error::CorruptHistory)?,
    )
    .map_err(|_| Error::CorruptHistory)?;
    if slot != row.index {
        return Err(Error::CorruptHistory);
    }
    Ok(head)
}
pub(crate) fn read_operation_slot(
    world: &impl WorldReadOnly,
    deployment: &str,
    operation_id: [u8; 32],
) -> Result<Option<NativeOperation>, Error> {
    if operation_id == [0; 32] {
        return Err(Error::Invalid);
    }
    let first = world
        .smart_contract_state()
        .get(&operation_admission_key(deployment, operation_id)?);
    let Some(bytes) = world
        .smart_contract_state()
        .get(&operation_slot_key(deployment, operation_id)?)
    else {
        if first.is_some() {
            return Err(Error::CorruptHistory);
        }
        return Ok(None);
    };
    let index: OperationIndexV1 = decode(bytes).map_err(|_| Error::CorruptHistory)?;
    let row = read_operation_record(world, deployment, index.head.revision)?;
    if row.index != index || row.record.intent.operation_id != operation_id {
        return Err(Error::CorruptHistory);
    }
    let first: OperationIndexV1 =
        decode(first.ok_or(Error::CorruptHistory)?).map_err(|_| Error::CorruptHistory)?;
    let reserved = read_operation_record(world, deployment, first.head.revision)?;
    if reserved.index != first
        || reserved.record.outcome != FinalPromotionOperationOutcomeV1::Reserved
        || reserved.record.intent != row.record.intent
        || reserved.record.custody != row.record.custody
        || reserved.record.reservation != row.record.reservation
        || reserved.record.reserved != row.record.reserved
    {
        return Err(Error::CorruptHistory);
    }
    if row.record.outcome == FinalPromotionOperationOutcomeV1::Reserved {
        let current = read_operation_head(world, deployment)?;
        if row.index.head != current || current.active_operation != Some(operation_id) {
            return Err(Error::CorruptHistory);
        }
    }
    Ok(Some(row))
}
/// Return the immutable admission revision after validating its current operation slot.
///
/// A later Complete/Expire/Invalidate rewrites the slot, never the original Reserved row.
/// Source proofs must use this admission index instead of treating the mutable slot as origin.
pub(crate) fn read_original_reserved_operation(
    world: &impl WorldReadOnly,
    deployment: &str,
    operation_id: [u8; 32],
) -> Result<Option<NativeOperation>, Error> {
    let Some(current) = read_operation_slot(world, deployment, operation_id)? else {
        return Ok(None);
    };
    let admission: OperationIndexV1 = decode(
        world
            .smart_contract_state()
            .get(&operation_admission_key(deployment, operation_id)?)
            .ok_or(Error::CorruptHistory)?,
    )
    .map_err(|_| Error::CorruptHistory)?;
    let reserved = read_operation_record(world, deployment, admission.head.revision)?;
    if reserved.index != admission
        || reserved.record.outcome != FinalPromotionOperationOutcomeV1::Reserved
        || reserved.record.intent.operation_id != operation_id
        || reserved.record.reserved_origin != current.record.reserved_origin
        || reserved.record.intent != current.record.intent
        || reserved.record.custody != current.record.custody
        || reserved.record.reservation != current.record.reservation
        || reserved.record.reserved != current.record.reserved
    {
        return Err(Error::CorruptHistory);
    }
    Ok(Some(reserved))
}
pub(crate) fn read_operation_head_at(
    world: &impl WorldReadOnly,
    deployment: &str,
    height: u64,
) -> Result<FinalPromotionOperationHeadV1, Error> {
    let active = read_operation_head(world, deployment)?;
    if active.revision == 0 {
        return Ok(active);
    }
    let entry = world
        .smart_contract_state()
        .range(
            operation_height_key(deployment, 0, 0)?
                ..=operation_height_key(deployment, height, u32::MAX)?,
        )
        .next_back();
    let Some((key, bytes)) = entry else {
        if read_operation_record(world, deployment, 1)?
            .record
            .execution
            .height
            <= height
        {
            return Err(Error::CorruptHistory);
        }
        return Ok(FinalPromotionOperationHeadV1::empty());
    };
    let index: OperationIndexV1 = decode(bytes).map_err(|_| Error::CorruptHistory)?;
    if key != &operation_height_key(deployment, index.height, index.ordinal)?
        || index.height > height
        || index.head.revision > active.revision
    {
        return Err(Error::CorruptHistory);
    }
    let selected = read_operation_record(world, deployment, index.head.revision)?;
    if selected.index != index {
        return Err(Error::CorruptHistory);
    }
    if index.head.revision < active.revision
        && read_operation_record(world, deployment, index.head.revision + 1)?
            .record
            .execution
            .height
            <= height
    {
        return Err(Error::CorruptHistory);
    }
    Ok(index.head)
}
pub(super) fn read_operation_at(
    world: &impl WorldReadOnly,
    deployment: &str,
    operation_id: [u8; 32],
    height: u64,
) -> Result<Option<FinalPromotionOperationRecordV1>, Error> {
    let Some(latest) = read_operation_slot(world, deployment, operation_id)? else {
        return Ok(None);
    };
    if latest.record.execution.height <= height {
        return Ok(Some(latest.record));
    }
    if latest.record.outcome == FinalPromotionOperationOutcomeV1::Reserved {
        return Ok(None);
    }
    let reserved = read_operation_record(
        world,
        deployment,
        latest
            .record
            .revision
            .checked_sub(1)
            .ok_or(Error::CorruptHistory)?,
    )?;
    if reserved.record.intent.operation_id != operation_id
        || reserved.record.outcome != FinalPromotionOperationOutcomeV1::Reserved
    {
        return Err(Error::CorruptHistory);
    }
    Ok((reserved.record.execution.height <= height).then_some(reserved.record))
}
