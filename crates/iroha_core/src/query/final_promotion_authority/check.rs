//! Shared no-write eligibility for native execution and a current applied observation cut.
use super::*;
use crate::smartcontracts::isi::helpers::world_account_has_permission as has_permission;
use iroha_data_model::{
    account::AccountId,
    isi::sorafs::MutateSorafsFinalPromotionAuthority,
    permission::Permission,
    sorafs::final_promotion_authority::{
        FinalPromotionAuthorityActionV1 as Action, FinalPromotionCheckSubjectV1 as Subject,
        FinalPromotionCheckV1,
    },
};
use iroha_executor_data_model::permission::sorafs::{
    CanCheckSorafsFinalPromotion, CanManageSorafsFinalPromotionCustody,
    CanOperateSorafsFinalPromotion,
};
use sorafs_manifest::signer::{
    custody::{SignerCustodyUseContextV1, VerifiedSignerCustodyV1, verify_signer_custody_use_v1},
    protocol::SignerOperationActionV1,
};

pub(crate) fn authorized(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    deployment: &str,
    action: &Action,
) -> bool {
    let permission: Permission = match action {
        Action::Configure(_) | Action::Enroll(_) | Action::Revoke(_) => {
            CanManageSorafsFinalPromotionCustody {
                deployment_id: deployment.to_owned(),
            }
            .into()
        }
        Action::Reserve(_) | Action::Complete(_) | Action::Expire(_) => {
            CanOperateSorafsFinalPromotion {
                deployment_id: deployment.to_owned(),
            }
            .into()
        }
        Action::Check(check) => {
            if authority == &check.expected_operator
                || !has_permission(
                    world,
                    &check.expected_operator,
                    CanOperateSorafsFinalPromotion {
                        deployment_id: deployment.to_owned(),
                    }
                    .into(),
                )
            {
                return false;
            }
            CanCheckSorafsFinalPromotion {
                deployment_id: deployment.to_owned(),
            }
            .into()
        }
    };
    has_permission(world, authority, permission)
}

pub(crate) fn check_floor(
    state: &impl StateReadOnly,
    check: &FinalPromotionCheckV1,
    execution_height: u64,
) -> Result<(), Error> {
    if check.challenge == [0; 32]
        || check.network_id == [0; 32]
        || check.minimum_block_hash == [0; 32]
        || check.network_id != *state.network_id().as_bytes()
        || check.minimum_height >= execution_height
    {
        return Err(Error::BindingMismatch);
    }
    let offset = check
        .minimum_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .ok_or(Error::HeightUnavailable)?;
    if state.block_hashes().get(offset).map(|hash| *hash.as_ref()) != Some(check.minimum_block_hash)
    {
        return Err(Error::HeightUnavailable);
    }
    Ok(())
}

/// Evaluate an exact phase against already validated native rows and current custody.
pub(crate) fn check_subject(
    check: &FinalPromotionCheckV1,
    observer: &AccountId,
    custody: &VerifiedSignerCustodyV1,
    head: &FinalPromotionOperationHeadV1,
    operation: Option<&FinalPromotionOperationRecordV1>,
    now: u64,
) -> Result<(), Error> {
    if observer == &check.expected_operator {
        return Err(Error::BindingMismatch);
    }
    if now == 0 || now == u64::MAX {
        return Err(Error::ReservationTime);
    }
    check
        .request
        .validate_custody(custody)
        .map_err(|_| Error::Custody)?;
    let (expected, reserved) = match &check.subject {
        Subject::Current(audit) => {
            return if *audit == head.audit {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        Subject::BeforeProvider(row) | Subject::AfterProvider(row) | Subject::BeforeCommit(row) => {
            (row, true)
        }
        Subject::AfterCommit(row) | Subject::BeforeRelease(row) => (row, false),
    };
    let row = operation.ok_or(Error::Conflict)?;
    let operation_matches = row.intent.operation_id == check.request.operation_id;
    if row != expected
        || !operation_matches
        || row.intent.request_digest != check.request.digest().map_err(|_| Error::Invalid)?
        || row.intent.action != SignerOperationActionV1::Sign
        || row.custody != check.request.original_custody
        || row.reserved.authority != check.expected_operator
        || row.execution.authority != check.expected_operator
    {
        return Err(Error::Conflict);
    }
    if now < row.execution.recorded_at_unix_ms {
        return Err(Error::ReservationTime);
    }
    if reserved {
        if row.outcome != FinalPromotionOperationOutcomeV1::Reserved
            || head.active_operation != Some(row.intent.operation_id)
            || row.revision != head.revision
            || operation::operation_digest(row)? != head.digest
            || row.intent.previous_audit != head.audit
        {
            return Err(Error::Conflict);
        }
        if now >= row.reservation.expires_at_unix_ms {
            return Err(Error::ReservationTime);
        }
    } else if !matches!(row.outcome, FinalPromotionOperationOutcomeV1::Completed(_)) {
        return Err(Error::Conflict);
    }
    // Native readers have already checked the complete retained reservation/completion history.
    // A completed row remains eligible after later operations and its reservation expiry; this
    // fresh custody check is deliberately independent of the idempotent Complete retry path.
    Ok(())
}

/// Re-read the authority and account grants from exactly the supplied current applied cut.
/// This does not authenticate the challenge, executed entry/result, committee lineage or time.
pub(crate) fn check_applied_snapshot_v1(
    view: &impl StateReadOnly,
    instruction: &MutateSorafsFinalPromotionAuthority,
    binding: &SignerCustodyBindingV1,
    observer: &AccountId,
    now: u64,
) -> Result<FinalPromotionAuthoritySnapshotV1, Error> {
    if !valid_deployment(&instruction.deployment_id) {
        return Err(Error::BindingMismatch);
    }
    let Action::Check(check) = &instruction.action else {
        return Err(Error::Invalid);
    };
    encode(instruction)?;
    let height = u64::try_from(view.block_hashes().len()).map_err(|_| Error::HeightUnavailable)?;
    check_floor(view, check, height)?;
    if !authorized(
        view.world(),
        observer,
        &instruction.deployment_id,
        &instruction.action,
    ) {
        return Err(Error::BindingMismatch);
    }
    validate_binding(view, binding, &instruction.deployment_id)?;
    let snapshot = read_final_promotion_authority_at_v1(
        view,
        binding,
        height,
        Some(check.request.operation_id),
    )?
    .ok_or(Error::Conflict)?;
    if snapshot.control_record.revision != instruction.expected_control_revision
        || snapshot.custody_anchor.state_digest != instruction.expected_control_digest
    {
        return Err(Error::Conflict);
    }
    check_snapshot_eligibility_v1(&snapshot, instruction, binding, observer, now, now)?;
    Ok(snapshot)
}

/// Recheck only custody and phase time against the same previously authenticated native snapshot.
/// The caller must already establish same-cut authorization, control CAS and retained history.
/// This helper does not authenticate a snapshot or qualify its independently supplied clock.
/// Preserve the independently observed earliest time when reusing a captured snapshot.
pub(super) fn check_snapshot_eligibility_v1(
    snapshot: &FinalPromotionAuthoritySnapshotV1,
    instruction: &MutateSorafsFinalPromotionAuthority,
    binding: &SignerCustodyBindingV1,
    observer: &AccountId,
    now: u64,
    anchor_observed_at_unix_ms: u64,
) -> Result<(), Error> {
    let Action::Check(check) = &instruction.action else {
        return Err(Error::Invalid);
    };
    // Trusted use time cannot precede the native control execution being claimed as current.
    if now < snapshot.control_record.execution.recorded_at_unix_ms {
        return Err(Error::Custody);
    }
    let custody = verify_signer_custody_use_v1(
        snapshot
            .control_record
            .enrollment
            .as_deref()
            .ok_or(Error::Custody)?,
        binding,
        &snapshot.control.policy.custody_trust(),
        &SignerCustodyUseContextV1 {
            now_unix_ms: now,
            anchor_observed_at_unix_ms,
            current_anchor: snapshot.custody_anchor,
            active_head: snapshot.control.active_head.ok_or(Error::Custody)?,
            signer_revoked: snapshot.control.signer_revoked,
            attester_revoked: snapshot.control.attester_revoked,
        },
    )
    .map_err(|_| Error::Custody)?;
    check_subject(
        check,
        observer,
        &custody,
        &snapshot.operations,
        snapshot.operation.as_ref(),
        now,
    )
}
